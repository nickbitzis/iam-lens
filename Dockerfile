# Build stage: resolve and install dependencies with uv into a virtualenv.
FROM python:3.12-slim AS build
COPY --from=ghcr.io/astral-sh/uv:0.8 /uv /usr/local/bin/uv
WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable

# Runtime stage: slim image, non-root user, the venv and the example environment.
FROM python:3.12-slim
RUN useradd --create-home --uid 10001 iamlens
WORKDIR /app
COPY --from=build --chown=iamlens:iamlens /app/.venv /app/.venv
COPY --chown=iamlens:iamlens examples ./examples
# Campaign state is written to /app/data at runtime, so the non-root user must own it.
RUN mkdir -p /app/data && chown iamlens:iamlens /app/data
USER iamlens
ENV PATH="/app/.venv/bin:$PATH" HOST=0.0.0.0 PORT=8839 \
    IAMLENS_DATA=/app/examples IAMLENS_STATE=/app/data
EXPOSE 8839
HEALTHCHECK --interval=15s --timeout=3s --start-period=40s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8839/healthz', timeout=2)"
CMD ["iamlens", "serve"]
