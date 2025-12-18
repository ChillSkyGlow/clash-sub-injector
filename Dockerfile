# ==================== 构建阶段（仅装依赖）====================
FROM ghcr.io/astral-sh/uv:python3.13-alpine AS builder

WORKDIR /app

# 【可选】Alpine 编译依赖（如需C扩展解开）
# RUN apk add --no-cache gcc musl-dev linux-headers

# 复制依赖配置文件
COPY pyproject.toml uv.lock ./

# 核心修复：用 POSIX 标准的 . 替代 source，适配 Alpine 的 ash shell
RUN uv venv .venv && \
    . .venv/bin/activate && \
    uv sync --no-dev && \
    uv cache clean

# ==================== 运行阶段（仅含应用和依赖）====================
FROM ghcr.io/astral-sh/uv:python3.13-alpine

# 创建非root用户（Alpine语法）
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup -h /app -s /sbin/nologin && \
    mkdir -p /app && \
    chown -R appuser:appgroup /app

WORKDIR /app

# 复制虚拟环境和代码
COPY --from=builder --chown=appuser:appgroup /app/.venv /app/.venv
COPY --chown=appuser:appgroup src/ /app/src/

# 切换非root用户
USER appuser

# 暴露端口
EXPOSE 25500

# 环境变量
ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH="/app" \
    PATH="/app/.venv/bin:$PATH"

# 启动命令
CMD ["gunicorn", "--bind", "0.0.0.0:25500", "src.main:app"]