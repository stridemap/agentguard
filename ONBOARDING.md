# AgentGuard — Pilot Customer Onboarding Guide

5-minute setup to govern your AI agents with AgentGuard.

---

## Step 1: Install (30 seconds)

```bash
pip install agentguard
```

## Step 2: Add to Your Agent (60 seconds)

```python
from agentguard import AgentGuardInterceptor

# Create the interceptor — that's it
interceptor = AgentGuardInterceptor(
    agent_id="your-agent-name",
    session_id="session-001",
    db_path="agentguard.db",              # SQLite for quick start
    policy_path="policies/default.yaml",   # YAML rules
    dlp_sensitivity="HIGH",                # PII scanning level
    injection_sensitivity="MEDIUM",        # Injection detection
)

# Add to your LangGraph/LangChain agent — zero code changes
config = {"callbacks": [interceptor]}
agent.invoke(input, config=config)
```

## Step 3: Verify It Works (60 seconds)

```bash
# Check events were captured
python -m agentguard verify-chain --db agentguard.db

# Run the built-in demo
python -m demo.finance_scenario
```

## Step 4: Start the Dashboard (60 seconds)

```bash
# Streamlit (quick)
streamlit run dashboard/app.py -- --db agentguard.db

# Or run the full API + Next.js dashboard
uvicorn api.main:app --reload
# Then open http://localhost:8000/docs
```

## Step 5: Write Your First Policy (2 minutes)

Create `policies/my_policy.yaml`:

```yaml
rules:
  - id: block_pii_external
    name: Block PII to External
    description: Prevent agents from sending PII to external domains
    priority: 10
    conditions:
      tool_name: "send_email|post_webhook"
      data_pattern: "US_SSN"
      direction: "output"
    action: BLOCK
    alert_severity: CRITICAL

  - id: allow_internal_tools
    name: Allow Internal Tools
    description: Allow all calls to internal endpoints
    priority: 100
    conditions:
      destination_domain: "internal.yourcompany.com"
    action: ALLOW
    alert_severity: LOW
```

---

## Production Deployment

### Option A: Docker Compose (Recommended for pilots)

```bash
git clone https://github.com/stridemap/agentguard
cd agentguard
docker compose up -d
```

Services:
- **API**: http://localhost:8000 (FastAPI + Swagger docs at /docs)
- **Dashboard**: http://localhost:8501 (Streamlit trace viewer)
- **PostgreSQL**: localhost:5432
- **Redis**: localhost:6379

### Option B: Helm Chart (Kubernetes)

```bash
helm install agentguard ./helm/agentguard \
  -f helm/agentguard/values-prod.yaml \
  --set api.jwtSecret="your-production-secret"
```

### Option C: pip install only (Embedded mode)

```bash
pip install agentguard
# No external infrastructure needed — SQLite + in-memory queue
```

---

## Configuration Reference

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `DATABASE_URL` | `sqlite:///agentguard.db` | Database URL (SQLite or PostgreSQL) |
| `AGENTGUARD_POLICY_PATH` | — | Path to YAML policy file |
| `AGENTGUARD_LLM_PROVIDER` | `mock` | LLM for injection classifier (ollama/openai/anthropic) |
| `AGENTGUARD_JWT_SECRET` | (dev default) | JWT signing secret — **change in production** |
| `AGENTGUARD_SIEM_WEBHOOK_URL` | — | SIEM webhook for CEF event forwarding |
| `AGENTGUARD_ALERT_WEBHOOK_URL` | — | Alert webhook (Slack/PagerDuty) |
| `AGENTGUARD_QUEUE_BACKEND` | `memory` | Queue backend (memory or redis) |
| `AGENTGUARD_REDIS_URL` | — | Redis URL for production queue |
| `AGENTGUARD_RETENTION_DAYS` | `90` | Data retention period |
| `AGENTGUARD_SSO_PROVIDER` | `none` | SSO provider (oidc/saml/none) |

---

## Compliance Reports

Generate audit evidence for your compliance team:

```bash
# Via API
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/compliance/soc2
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/compliance/hipaa
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/compliance/iso27001

# Check retention status
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/compliance/retention/status?regulation=hipaa
```

---

## Support

- **GitHub Issues**: https://github.com/stridemap/agentguard/issues
- **Email**: support@stridemap.ai
- **Documentation**: https://github.com/stridemap/agentguard#readme
