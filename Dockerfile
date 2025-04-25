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
