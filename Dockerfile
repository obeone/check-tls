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

# Copy only necessary files for dependency installation
COPY --link pyproject.toml ./

# Create a virtual environment and activate it for subsequent commands
# Install dependencies using pip cache
RUN  --mount=type=cache,target=/root/.cache/pip \
    python -m venv /opt/venv && \
    . /opt/venv/bin/activate && \
    pip install --upgrade pip


# Copy the rest of the source code after dependency installation
COPY --link src/ ./src/

# Install the project using pip cache, including versioning from git tags
RUN  --mount=type=cache,target=/root/.cache/pip \
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
RUN addgroup -S -g 1001 appgroup && \
    adduser -S -u 1001 -G appgroup appuser

WORKDIR /app

RUN --mount=type=cache,target=/root/.cache/pip \
    --mount=type=bind,from=builder,source=/app/dist,target=/app/dist \
    pip install /app/dist/*.whl

USER appuser

EXPOSE 8000

ENTRYPOINT ["check-tls"]

# Metadata Labels - ensure APP_VERSION is correctly interpolated
LABEL org.opencontainers.image.title="Check TLS Bundle" \
      org.opencontainers.image.description="A versatile Python tool to analyze TLS/SSL certificates for one or multiple domains, featuring profile detection, chain validation, and multiple output formats. Includes a handy web interface mode!" \
      org.opencontainers.image.url="https://github.com/obeone/check-tls" \
      org.opencontainers.image.source="https://github.com/obeone/check-tls" \
      org.opencontainers.image.version="${APP_VERSION}" \
      org.opencontainers.image.vendor="Grégoire Compagnon - obeone" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.authors="Grégoire Compagnon - obeone <opensource@obeone.org>"
