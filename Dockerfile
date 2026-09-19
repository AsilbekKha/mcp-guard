FROM python:3.11-slim AS builder

WORKDIR /app

COPY pyproject.toml README.md ./
COPY mcp_guard ./mcp_guard

RUN pip install --no-cache-dir --prefix=/install .


FROM python:3.11-slim

COPY --from=builder /install /usr/local

ENTRYPOINT ["mcp-guard"]
