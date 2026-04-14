# AgentGuard — Multi-stage Docker build
# Target: < 200MB image

# ── Stage 1: Build ───────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY agentguard/ agentguard/
COPY api/ api/

RUN pip install --no-cache-dir --target=/install .

# ── Stage 2: Runtime ─────────────────────────────────────────────────
FROM python:3.11-slim

WORKDIR /app

# Copy installed packages
COPY --from=builder /install /usr/local/lib/python3.11/site-packages/

# Copy application code
COPY agentguard/ agentguard/
COPY api/ api/
COPY policies/ policies/
COPY dashboard/ dashboard/
COPY alembic/ alembic/
COPY alembic.ini .

# Default environment
ENV DATABASE_URL=sqlite:///agentguard.db \
    AGENTGUARD_LLM_PROVIDER=mock \
    AGENTGUARD_LOG_LEVEL=INFO \
    AGENTGUARD_POLICY_PATH=policies/default.yaml \
    AGENTGUARD_JWT_SECRET=change-me-in-production

EXPOSE 8000

# Run the API server
CMD ["python", "-m", "uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
