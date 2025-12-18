import ipaddress
import logging
import re
import socket

# 新增安全相关依赖导入
import urllib.parse
from typing import TYPE_CHECKING, Any, Dict, Optional, Union

import requests
import yaml
from flask import Flask, make_response, request

# 速率限制依赖导入
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# 配置日志（移到顶部，符合导入规范）
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(module)s:%(funcName)s:%(lineno)d - %(message)s",  # 增加模块、函数、行号信息
)
logger = logging.getLogger(__name__)

# 类型检查时导入CommentedMap，运行时不导入（避免未安装ruamel时出错）
if TYPE_CHECKING:
    try:
        from ruamel.yaml.comments import CommentedMap
    except ImportError:
        CommentedMap = Dict[str, Any]  # 降级为普通字典类型

# 尝试导入ruamel.yaml，若失败则使用标准yaml
try:
    from ruamel.yaml import YAML
    from ruamel.yaml.comments import CommentedMap as RuamelCommentedMap

    RUAMEL_AVAILABLE = True
    # 初始化ruamel.yaml
    yaml_loader = YAML()
    yaml_loader.preserve_quotes = True
    yaml_loader.indent(mapping=2, sequence=4, offset=2)
    logger.info("成功导入ruamel.yaml，将保留YAML注释和格式")
except ImportError:
    RUAMEL_AVAILABLE = False
    RuamelCommentedMap = Dict[str, Any]  # 定义别名，避免引用错误
    logger.warning("未安装ruamel.yaml，将使用标准yaml库，可能会丢失注释格式")

app = Flask(__name__)
app.config["JSON_AS_ASCII"] = False

# 初始化请求速率限制器（按访问IP限制）
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["100 per day", "30 per hour"],  # 全局默认访问限制
    storage_uri="memory://",  # 内存存储（生产环境建议改用Redis）
)
logger.info("速率限制器初始化完成，全局默认限制：100次/天，30次/小时")


def is_safe_url(url: str) -> bool:
    """验证URL安全性，防SSRF：仅允许http/https，禁止访问私有IP（排除Clash Fake-IP）"""

    def is_clash_fake_ip(ip: str) -> bool:
        """判断IP是否属于Clash Fake-IP默认网段（198.18.0.0/15）"""
        try:
            ip_addr = ipaddress.ip_address(ip)
            fake_ip_range = ipaddress.ip_network("198.18.0.0/16")  # Clash默认Fake-IP网段
            return ip_addr in fake_ip_range
        except ValueError:
            logger.warning(f"IP地址格式无效：{ip}，无法判断是否为Clash Fake-IP")
            return False

    try:
        parsed_url = urllib.parse.urlparse(url)
        if parsed_url.scheme not in ("http", "https"):
            logger.warning(f"URL安全校验失败：{url} 协议非法（{parsed_url.scheme}），仅允许http/https")
            return False
        hostname = parsed_url.hostname
        if not hostname:
            logger.warning(f"URL安全校验失败：{url} 无有效主机名")
            return False
        # 解析主机IP
        logger.info(f"开始解析URL主机名：{hostname}（来自URL：{url}）")
        ip_list = socket.gethostbyname_ex(hostname)[2]
        logger.info(f"URL {url} 解析出IP列表: {ip_list}")
        # 检查每个IP是否为私有IP（排除Clash Fake-IP）
        for ip in ip_list:
            if is_clash_fake_ip(ip):
                logger.info(f"IP {ip} 属于Clash Fake-IP网段，跳过私有IP检查")
                continue
            if ipaddress.ip_address(ip).is_private:
                logger.warning(f"URL安全校验失败：{url} 包含私有IP: {ip}")
                return False
        logger.info(f"URL {url} 安全校验通过")
        return True
    except Exception as e:
        logger.error(f"URL {url} 安全校验过程出错：{str(e)}", exc_info=True)  # 记录异常堆栈
        return False


def is_safe_url1(url: str) -> bool:
    """验证URL安全性，防SSRF：仅允许http/https，禁止访问私有IP"""
    try:
        parsed_url = urllib.parse.urlparse(url)
        # 仅允许HTTP/HTTPS协议
        if parsed_url.scheme not in ("http", "https"):
            logger.warning(f"URL安全校验（严格模式）失败：{url} 协议非法（{parsed_url.scheme}）")
            return False
        # 校验主机名有效性
        hostname = parsed_url.hostname
        if not hostname:
            logger.warning(f"URL安全校验（严格模式）失败：{url} 无有效主机名")
            return False
        # 解析主机对应的所有IP，禁止私有IP（内网、回环等）
        ip_list = socket.gethostbyname_ex(hostname)[2]
        logger.info(f"URL {url}（严格模式）解析出IP列表: {ip_list}")
        for ip in ip_list:
            if ipaddress.ip_address(ip).is_private:
                logger.warning(f"URL安全校验（严格模式）失败：{url} 包含私有IP: {ip}")
                return False
        logger.info(f"URL {url}（严格模式）安全校验通过")
        return True
    except Exception as e:
        logger.error(f"URL（严格模式）安全校验出错：{str(e)}", exc_info=True)
        return False


def load_yaml_with_comments(content: str) -> Union[Dict[str, Any], RuamelCommentedMap]:
    """加载YAML并保留注释和格式（支持ruamel和标准yaml）"""
    logger.info(f"开始加载YAML内容（长度：{len(content)}字符）")
    if RUAMEL_AVAILABLE:
        try:
            data = yaml_loader.load(content)
            logger.info("使用ruamel.yaml成功加载YAML内容，保留注释和格式")
            return data
        except Exception as e:
            logger.error(f"ruamel.yaml加载YAML失败，将降级使用标准yaml: {str(e)}", exc_info=True)
            return yaml.safe_load(content)
    else:
        try:
            data = yaml.safe_load(content)
            logger.info("使用标准yaml库成功加载YAML内容")
            return data
        except yaml.YAMLError as e:
            logger.error(f"标准yaml库加载YAML失败: {str(e)}", exc_info=True)
            raise  # 抛出异常由调用方处理


def dump_yaml_with_comments(data: Union[Dict[str, Any], RuamelCommentedMap]) -> str:
    """序列化YAML并保留注释和格式（支持ruamel和标准yaml）"""
    logger.info(f"开始序列化YAML数据（类型：{type(data).__name__}）")
    if RUAMEL_AVAILABLE and isinstance(data, RuamelCommentedMap):
        from io import StringIO

        try:
            buf = StringIO()
            yaml_loader.dump(data, buf)
            yaml_str = buf.getvalue()
            logger.info(f"使用ruamel.yaml成功序列化YAML（长度：{len(yaml_str)}字符）")
            return yaml_str
        except Exception as e:
            logger.error(f"ruamel.yaml序列化YAML失败，降级使用标准yaml: {str(e)}", exc_info=True)
    # 标准yaml处理
    try:
        yaml_str = yaml.dump(data, sort_keys=False, allow_unicode=True, default_flow_style=False)
        logger.info(f"使用标准yaml库成功序列化YAML（长度：{len(yaml_str)}字符）")
        return yaml_str
    except yaml.YAMLError as e:
        logger.error(f"标准yaml库序列化YAML失败: {str(e)}", exc_info=True)
        raise


def fetch_template(config_url: str) -> Optional[str]:
    """下载配置模板，限制最大1MB，防大文件DoS"""
    max_size = 1 * 1024 * 1024  # 最大允许1MB模板
    logger.info(f"开始下载配置模板：{config_url}，最大允许大小：{max_size / 1024 / 1024}MB")
    try:
        # 流式下载，分段校验大小
        response = requests.get(
            config_url,
            timeout=10,  # 缩短超时，减少资源占用
            headers={"User-Agent": "Clash-Sub-Proxy/1.0"},
            stream=True,
        )
        response.raise_for_status()  # 抛出HTTP错误
        logger.info(f"模板下载请求成功，响应状态码：{response.status_code}")

        template_chunks = []
        total_size = 0
        for chunk in response.iter_content(chunk_size=1024):
            total_size += len(chunk)
            if total_size > max_size:
                logger.error(f"配置模板超过大小限制（{max_size}字节），当前已下载：{total_size}字节，终止下载")
                return None
            template_chunks.append(chunk)
        # 合并内容并解码
        template_content = b"".join(template_chunks).decode("utf-8")
        logger.info(f"配置模板下载成功，实际大小：{len(template_content)}字符（{total_size}字节）")
        return template_content
    except requests.exceptions.RequestException as e:
        logger.error(f"下载模板失败（URL：{config_url}）: {str(e)}", exc_info=True)
        return None


def create_proxy_provider_entry(name: str, url: str) -> Dict[str, Any]:
    """创建proxy-providers配置项"""
    logger.info(f"开始创建proxy-provider配置项，名称：{name}，目标URL：{url}")
    entry = {
        name: {
            "url": url,
            "type": "http",
            "interval": 86400,
            "header": {"User-Agent": ["Clash"]},
            "health-check": {"enable": True, "url": "https://www.gstatic.com/generate_204", "interval": 300},
            "proxy": "直连",
        }
    }
    logger.info(f"proxy-provider配置项创建完成：{name}")
    return entry


def inject_proxy_provider(template_content: str, new_entry: Dict[str, Any]) -> Optional[str]:
    """将新配置嵌入到模板的proxy-providers中"""
    entry_name = next(iter(new_entry.keys()))  # 获取配置项名称
    logger.info(f"开始向模板注入proxy-provider配置，名称：{entry_name}")
    try:
        # 加载YAML模板
        yaml_data = load_yaml_with_comments(template_content)
        # 确保yaml_data是字典类型
        if not isinstance(yaml_data, (dict, RuamelCommentedMap)):
            logger.error("YAML模板格式错误，根节点必须是字典类型")
            return None
        # 确保proxy-providers节点存在
        if "proxy-providers" not in yaml_data:
            logger.info("模板中未找到proxy-providers节点，将创建新节点")
            if RUAMEL_AVAILABLE:
                yaml_data["proxy-providers"] = RuamelCommentedMap()
            else:
                yaml_data["proxy-providers"] = {}
        # 添加新的配置项（如果已存在则覆盖）
        proxy_providers = yaml_data["proxy-providers"]
        if isinstance(proxy_providers, (dict, RuamelCommentedMap)):
            if entry_name in proxy_providers:
                logger.warning(f"proxy-providers中已存在{entry_name}，将覆盖现有配置")
            proxy_providers.update(new_entry)
            logger.info(f"成功向proxy-providers注入配置：{entry_name}")
        else:
            logger.error(f"proxy-providers节点类型错误（{type(proxy_providers).__name__}），无法注入配置")
            return None
        # 序列化回YAML字符串
        return dump_yaml_with_comments(yaml_data)
    except yaml.YAMLError as e:
        logger.error(f"解析或修改YAML失败（配置项：{entry_name}）: {str(e)}", exc_info=True)
        return None
    except Exception as e:
        logger.error(f"处理YAML配置失败（配置项：{entry_name}）: {str(e)}", exc_info=True)
        return None


def fetch_url_headers(target_url: str) -> Dict[str, str]:
    """以User-Agent: Clash访问目标URL，获取指定响应头"""
    required_headers = ["content-disposition", "profile-update-interval", "subscription-userinfo", "profile-web-page-url"]
    logger.info(f"开始获取目标URL响应头：{target_url}，需要的头信息：{required_headers}")
    result = {}
    try:
        # 优先使用HEAD请求
        response = requests.head(target_url, timeout=15, headers={"User-Agent": "Clash"}, allow_redirects=True)
        logger.info(f"HEAD请求响应状态码：{response.status_code}")
        # 若HEAD请求失败，尝试GET（仅获取头）
        if response.status_code not in [200, 204]:
            logger.warning(f"HEAD请求返回非成功状态码（{response.status_code}），尝试GET请求")
            response = requests.get(target_url, timeout=15, headers={"User-Agent": "Clash"}, allow_redirects=True, stream=True)
            response.close()  # 不下载响应体
            logger.info(f"GET请求响应状态码：{response.status_code}")
        # 提取需要的响应头（忽略大小写）
        response_headers = {k.lower(): v for k, v in response.headers.items()}
        for header in required_headers:
            if header in response_headers:
                result[header] = response_headers[header]
                logger.info(f"成功获取头信息：{header} = {response_headers[header][:50]}...")  # 截断长值
        logger.info(f"目标URL响应头获取完成，共获取{len(result)}个需要的头信息")
    except requests.exceptions.RequestException as e:
        logger.warning(f"获取目标URL（{target_url}）响应头失败: {str(e)}", exc_info=True)
    return result


@app.route("/sub", methods=["GET"])
@limiter.limit("10 per minute")  # 接口专属限制：每分钟最多10次请求
def sub():
    # 记录请求基本信息
    client_ip = get_remote_address()
    logger.info(f"收到新的/sub请求，客户端IP：{client_ip}，请求参数：{dict(request.args)}")

    # 1. 获取请求参数
    url = request.args.get("url", "")
    name = request.args.get("name", "")
    config = request.args.get("config", "")

    # 2. 强化参数校验（防非法输入、DoS、SSRF）
    # 校验参数非空及字符串类型
    if not url or not isinstance(url, str):
        logger.warning(f"参数校验失败：url为空或非字符串（客户端IP：{client_ip}）")
        return make_response({"error": "参数错误", "message": "url需为有效字符串"}, 400)
    if not name or not isinstance(name, str):
        logger.warning(f"参数校验失败：name为空或非字符串（客户端IP：{client_ip}）")
        return make_response({"error": "参数错误", "message": "name需为有效字符串"}, 400)
    if not config or not isinstance(config, str):
        logger.warning(f"参数校验失败：config为空或非字符串（客户端IP：{client_ip}）")
        return make_response({"error": "参数错误", "message": "config需为有效字符串"}, 400)

    # 限制参数长度
    if len(url) > 2048:
        logger.warning(f"参数校验失败：url长度超限（{len(url)} > 2048）（客户端IP：{client_ip}）")
        return make_response({"error": "参数错误", "message": "URL长度不可超过2048字符"}, 400)
    if len(config) > 2048:
        logger.warning(f"参数校验失败：config长度超限（{len(config)} > 2048）（客户端IP：{client_ip}）")
        return make_response({"error": "参数错误", "message": "config长度不可超过2048字符"}, 400)
    if len(name) > 100:
        logger.warning(f"参数校验失败：name长度超限（{len(name)} > 100）（客户端IP：{client_ip}）")
        return make_response({"error": "参数错误", "message": "名称长度不可超过100字符"}, 400)

    # 校验name字符集
    if not re.match(r"^[a-zA-Z0-9_\-\u4e00-\u9fa5]+$", name):
        logger.warning(f"参数校验失败：name包含非法字符（{name}）（客户端IP：{client_ip}）")
        return make_response({"error": "参数错误", "message": "名称仅支持中文、字母、数字、下划线、连字符"}, 400)

    # 校验URL安全性（防SSRF）
    if not is_safe_url(url):
        logger.warning(f"参数校验失败：url不安全（{url}）（客户端IP：{client_ip}）")
        return make_response({"error": "参数错误", "message": "URL禁止访问私有网络或非HTTP/HTTPS协议"}, 400)
    if not is_safe_url(config):
        logger.warning(f"参数校验失败：config不安全（{config}）（客户端IP：{client_ip}）")
        return make_response({"error": "参数错误", "message": "config URL禁止访问私有网络或非HTTP/HTTPS协议"}, 400)

    # 3. 下载配置模板
    logger.info(f"开始处理请求 - name: {name}, url: {url}, config: {config}（客户端IP：{client_ip}）")
    template_content = fetch_template(config)
    if not template_content:
        logger.error(f"请求处理失败：模板下载失败（config：{config}）（客户端IP：{client_ip}）")
        return make_response({"error": "模板下载失败", "message": "无法下载配置模板，请检查参数有效性"}, 500)

    # 4. 创建新的proxy-providers配置项
    new_provider = create_proxy_provider_entry(name, url)

    # 5. 将新配置嵌入模板
    modified_template = inject_proxy_provider(template_content, new_provider)
    if not modified_template:
        logger.error(f"请求处理失败：YAML处理失败（name：{name}）（客户端IP：{client_ip}）")
        return make_response({"error": "YAML处理失败", "message": "无法解析或修改配置模板"}, 500)

    # 6. 获取目标URL的响应头
    target_headers = fetch_url_headers(url)

    # 7. 构建响应
    response = make_response(modified_template, 200)
    response.headers["Content-Type"] = "application/x-yaml; charset=utf-8"
    for header_name, header_value in target_headers.items():
        response.headers[header_name] = header_value
        logger.info(f"添加响应头：{header_name} = {header_value[:50]}...")

    logger.info(f"请求处理成功 - name: {name}（客户端IP：{client_ip}，响应长度：{len(modified_template)}字符）")
    return response


if __name__ == "__main__":
    logger.info("应用启动中...")
    # 生产环境务必替换为Gunicorn等WSGI服务器
    app.run(
        host="0.0.0.0",  # VPS部署需监听公网地址
        port=25500,
        debug=False,  # 生产环境强制关闭debug
    )
    logger.info("应用已停止")
