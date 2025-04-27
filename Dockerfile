# syntax=docker/dockerfile:1

# --- Build Stage ---
    FROM python:3.13-alpine AS builder

    # Install build dependencies + Rust
    RUN apk add --no-cache \
          gcc \
          musl-dev \
          libffi-dev \
          python3-dev \
          openssl-dev \
          py3-pip \
          rust \
          cargo
    
    WORKDIR /app
    
    # Copy only necessary files
    COPY --link setup.py ./
    COPY --link src/ ./src/
    
    # Create virtual environment and install dependencies
    RUN python -m venv /opt/venv
    
    RUN --mount=type=cache,target=/root/.cache/pip \
        . /opt/venv/bin/activate && \
        pip install --upgrade pip && \
        pip install .
    
    # --- Final Stage ---
    FROM python:3.13-alpine
    
    # Set environment variables
    ENV VIRTUAL_ENV=/opt/venv
    ENV PATH="$VIRTUAL_ENV/bin:$PATH"
    
    # Create a non-root user
    RUN addgroup -S app && adduser -S appuser -G app
    
    WORKDIR /app
    
    # Copy virtual environment from builder
    COPY --from=builder /opt/venv /opt/venv
    
    # Copy app source if needed
    COPY --link src/ ./src/
    COPY --link setup.py ./
    
    USER appuser
    
    EXPOSE 8000
    
    ENTRYPOINT ["check-tls"]
    
    # Metadata Labels
    LABEL org.opencontainers.image.title="Check TLS Bundle" \
          org.opencontainers.image.description="A versatile Python tool to analyze TLS/SSL certificates for one or multiple domains, featuring profile detection, chain validation, and multiple output formats. Includes a handy web interface mode!" \
          org.opencontainers.image.url="https://github.com/obeone/check-tls" \
          org.opencontainers.image.source="https://github.com/obeone/check-tls" \
          org.opencontainers.image.version="0.1.0" \
          org.opencontainers.image.vendor="Grégoire Compagnon - obeone" \
          org.opencontainers.image.licenses="MIT" \
          org.opencontainers.image.authors="Grégoire Compagnon - obeone <opensource@obeone.org>"
