# syntax=docker/dockerfile:1
# MIT License - Author: Grégoire Compagnon (obeone) (https://github.com/obeone)

FROM python:3.13-slim

# Create non-root user early to improve layer caching
RUN addgroup --system app && adduser --system --ingroup app appuser

WORKDIR /app

# Install Python dependencies with persistent cache
COPY --link check_tls.py setup.py ./
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install .

USER appuser

ENTRYPOINT ["check-tls"]

# Metadata Labels
LABEL org.opencontainers.image.title="Check TLS Bundle"
LABEL org.opencontainers.image.description="A tool to check TLS bundles"
LABEL org.opencontainers.image.url="https://github.com/obeone/check-tls"
LABEL org.opencontainers.image.source="https://github.com/obeone/check-tls"
LABEL org.opencontainers.image.version="0.1.0"
LABEL org.opencontainers.image.vendor="Grégoire Compagnon - obeone"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.authors="Grégoire Compagnon - obeone <opensource@obeone.org>"
