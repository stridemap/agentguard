# AgentGuard — Production multi-stage Docker build
# Target: < 200MB final image
# Usage:
#   docker build -t agentguard .
#   docker run -p 8000:8000 agentguard

# ── Stage 1: Build dependencies ─────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy only dependency files first (cache layer)
COPY pyproject.toml README.md LICENSE ./
COPY agentguard/__init__.py agentguard/__init__.py

# Install Python deps into /install
RUN pip install --no-cache-dir --prefix=/install .

# ── Stage 2: Runtime ────────────────────────────────────────────────
FROM python:3.11-slim

LABEL org.opencontainers.image.source="https://github.com/stridemap/agentguard"
LABEL org.opencontainers.image.title="AgentGuard"
LABEL org.opencontainers.image.description="Guardrails and policy enforcement for AI agents"
LABEL org.opencontainers.image.vendor="Stridemap"

# Install runtime deps only (libpq for psycopg2)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 curl && \
    rm -rf /var/lib/apt/lists/* && \
    useradd --create-home --shell /bin/bash agentguard

WORKDIR /app

# Copy installed Python packages
COPY --from=builder /install /usr/local

# Copy application code
COPY agentguard/ agentguard/
COPY api/ api/
COPY policies/ policies/
COPY dashboard/ dashboard/
COPY alembic/ alembic/
COPY alembic.ini .

# Own files by non-root user
RUN chown -R agentguard:agentguard /app
USER agentguard

# Default environment
ENV DATABASE_URL=sqlite:///agentguard.db \
    AGENTGUARD_LLM_PROVIDER=mock \
    AGENTGUARD_LOG_LEVEL=INFO \
    AGENTGUARD_POLICY_PATH=policies/default.yaml \
    AGENTGUARD_JWT_SECRET=change-me-in-production \
    PYTHONUNBUFFERED=1

EXPOSE 8000

# Health check for Docker + K8s
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run API server
CMD ["python", "-m", "uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
