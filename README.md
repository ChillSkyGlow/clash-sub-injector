# clash-sub-injector

基于 Clash 订阅配置模板注入 `proxy-provider` 的轻量服务。

> 将用户提供的 proxy 提供者（proxy-provider）注入到一个 Clash 订阅配置模板中，生成可直接使用的 Clash 订阅 YAML。适合需要动态拼装/发布订阅的场景。

---

## 主要功能

- 从远程下载 Clash 配置模板（支持保留注释的 `ruamel.yaml`，回退到标准 `yaml`）。
- 将用户指定的 `proxy-provider` 项注入 `proxy-providers` 节点（若不存在则创建）。
- 返回生成后的 Clash YAML，同步转发目标 URL 的部分响应头（如 `subscription-userinfo` 等）。
- 内置 SSRF 防护、请求速率限制、模板大小限制等多项安全策略。

---

## 依赖

项目主文件（示例：`main.py`）中使用了以下主力依赖：

- Flask
- requests
- PyYAML（或 ruamel.yaml 可选，用于保留注释）
- flask-limiter

> 使用包管理器 `uv`：

```bash
# 使用 uv：
uv sync
```

---

## 使用方法（运行与演示）

### 启动服务（开发/测试）

```bash
uv run main.py
# 生产建议使用 gunicorn/uvicorn 等 WSGI/ASGI 容器
# 例如：gunicorn -w 4 -b 0.0.0.0:25500 main:app
```

### HTTP 接口

**GET** `/sub`

参数：

- `url`（必需）: 目标 proxy-provider 地址（http/https）。
- `name`（必需）: 注入到模板的 proxy-provider 名称（只允许中文/字母/数字/下划线/连字符）。
- `config`（必需）: 存放 Clash 配置模板的 URL（http/https）。

示例：

```bash
curl -sG "http://127.0.0.1:25500/sub" \
  --data-urlencode "url=https://example.com/provider.yaml" \
  --data-urlencode "name=my-provider" \
  --data-urlencode "config=https://example.com/clash-template.yaml" \
  -o clash-sub.yaml
```

响应：

- 成功返回 `200`，响应体为注入后的 YAML，`Content-Type: application/x-yaml; charset=utf-8`。
- 可能会有额外的 header（例如 `subscription-userinfo`、`profile-update-interval`），从目标 `url` 获取并转发。

---

## 安全与限制

- 服务内置 SSRF 防护：仅允许 `http` / `https`，会解析主机 IP 并阻止私有网段访问（对 Clash Fake-IP 段做特殊处理允许通过）。
- 模板下载大小限制（默认 1MB）以防止大文件 DoS。
- 请求速率限制：全局默认 `100/day`、`30/hour`，接口级别 `10/minute`（可在代码中调整）。
- 对用户输入（`name`、`url`、`config`）进行严格校验，限制字符集与长度。

---

## 开发注意事项

- 若需要保留模板的注释与原始格式，建议安装 `ruamel.yaml`，代码会自动优先使用它；否则使用标准 `PyYAML`，可能会丢失注释。
- 生产部署请使用成熟的 WSGI/ASGI 容器（Gunicorn、Uvicorn 等），并把速率限制存储切换到 Redis（`flask-limiter` 支持多种后端）。
- 日志已经启用，可根据需要调整日志级别与输出格式。

---

## 示例工作流

1. 客户端请求 `/sub?url=<provider_url>&name=<provider_name>&config=<template_url>`。
2. 服务校验参数及 URL 的合法性与安全性。
3. 下载模板（限制 1MB），解析为 YAML。
4. 将 `proxy-provider` 项以 `name` 注入到 `proxy-providers` 节点（存在则覆盖）。
5. 序列化回 YAML，返回给客户端并转发目标 `url` 的相关头部信息。

---

## 常见问题（FAQ）

- **Q**: 模板中已经有同名 `proxy-provider`，会怎样？

  - **A**: 当前实现会覆盖已存在的同名条目，并在日志中记录警告。

- **Q**: 我不用 `ruamel.yaml` 会丢失什么？

  - **A**: 主要是注释、原有键的顺序与格式化细节会被标准 `yaml` 库重写。

---

## 许可

MIT License。欢迎 Fork、Issue 和 PR。

---

## 联系

有问题请在仓库中打开 Issue，或在代码中查看 `logger` 输出定位问题。
