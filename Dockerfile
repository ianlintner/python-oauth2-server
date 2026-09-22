# syntax=docker/dockerfile:1
# `python:3.12-slim` pinned to the reviewed OCI manifest digest.
FROM python:3.12-slim@sha256:2fe5997d249a808b8eeea52c58a1dbffbba28754dc11699ef5c029f2d818ce79

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    OAUTH2_WORKERS=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PATH="/app/.venv/bin:$PATH"

RUN groupadd --gid 10001 oauth2 \
    && useradd --uid 10001 --gid oauth2 --create-home --home-dir /app oauth2

WORKDIR /app

# Install locked production dependencies before application source to retain
# Docker's dependency-layer cache across source-only builds.
COPY pyproject.toml uv.lock ./
RUN pip install --no-cache-dir "uv==0.10.12" \
    && uv sync --frozen --no-dev --no-install-project

COPY src ./src
RUN uv sync --frozen --no-dev \
    && chown -R oauth2:oauth2 /app

USER oauth2

EXPOSE 8080

# Production settings must include OAUTH2_JWT_SECRET and OAUTH2_PUBLIC_URL.
# The app validates insecure JWT secrets before binding its listener.
CMD ["python", "-m", "oauth2_server"]
