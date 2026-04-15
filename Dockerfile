# AgentGuard — Production Docker build
# Optimized for Railway / cloud deployment

FROM python:3.11-slim

LABEL org.opencontainers.image.source="https://github.com/stridemap/agentguard"

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy and install Python deps
COPY pyproject.toml README.md LICENSE ./
COPY agentguard/ agentguard/
COPY api/ api/
RUN pip install --no-cache-dir . pyyaml httpx psycopg2-binary

# Copy remaining files
COPY policies/ policies/
COPY dashboard/ dashboard/
COPY alembic/ alembic/
COPY alembic.ini .

ENV PYTHONUNBUFFERED=1

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -sf http://localhost:${PORT:-8000}/health || exit 1

CMD ["sh", "-c", "uvicorn api.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
