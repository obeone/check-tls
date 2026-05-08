# syntax=docker/dockerfile:1

# --- Build Stage ---
FROM python:3.13-alpine AS builder

ARG APP_VERSION=0.0.0

# Install build dependencies + Rust using APK cache
# This is more efficient than --no-cache for repeated builds
RUN --mount=type=cache,target=/var/cache/apk \
    apk add \
        gcc \
        musl-dev \
        libffi-dev \
        python3-dev \
        openssl-dev \
        py3-pip \
        rust \
        cargo

WORKDIR /app

# Copy sources for the wheel build (pyproject + src). pip wheel resolves
# transitive deps too, so /app/dist ends up containing every wheel needed.
COPY --link pyproject.toml ./
COPY --link src/ ./src/

RUN --mount=type=cache,target=/root/.cache/pip \
    SETUPTOOLS_SCM_PRETEND_VERSION=${APP_VERSION} pip wheel --wheel-dir=/app/dist/ .

# --- Final Stage ---
FROM python:3.13-alpine AS final

# Declare global ARGs so they are available throughout the FROM scope
ARG APP_VERSION

# Python specific ENV vars for best practices
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Create a non-root group and user for the application
# Using static IDs is a good practice for reproducibility
RUN addgroup -S -g 10001 appgroup && \
    adduser -S -u 10001 -G appgroup appuser

WORKDIR /app

RUN --mount=type=cache,target=/root/.cache/pip \
    --mount=type=bind,from=builder,source=/app/dist,target=/app/dist \
    pip install --no-index --find-links=/app/dist check-tls

USER appuser

EXPOSE 8000

ENTRYPOINT ["check-tls"]

# Healthcheck only meaningful when run with `--server`. For the default CLI
# entrypoint the container exits quickly and the healthcheck is a no-op.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget --quiet --tries=1 --spider http://localhost:8000/ || exit 1

# Metadata Labels - ensure APP_VERSION is correctly interpolated
LABEL org.opencontainers.image.title="Check TLS Bundle" \
      org.opencontainers.image.description="A versatile Python tool to analyze TLS/SSL certificates for one or multiple domains, featuring profile detection, chain validation, and multiple output formats. Includes a handy web interface mode!" \
      org.opencontainers.image.url="https://github.com/obeone/check-tls" \
      org.opencontainers.image.source="https://github.com/obeone/check-tls" \
      org.opencontainers.image.version="${APP_VERSION}" \
      org.opencontainers.image.vendor="Grégoire Compagnon - obeone" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.authors="Grégoire Compagnon - obeone <opensource@obeone.org>"
