# Changelog

All notable changes to AgentGuard are documented here.

## [1.0.0] — 2026-04-13

### Added

#### Core Library
- **Interceptor**: LangGraph `BaseCallbackHandler` with fail-open guarantee, zero agent code changes
- **Policy Engine v2**: YAML rules with ALLOW/BLOCK/ALERT/BYPASS, regex conditions (`input_regex`, `output_regex`), AND/OR match modes, hot-reload, <5ms p99 evaluation
- **DLP Scanner**: Microsoft Presidio PII detection — 15+ entity types, 3 sensitivity levels (LOW/MEDIUM/HIGH), 100% local, zero data egress
- **Injection Detector**: Two-stage defense — 21 regex patterns (OWASP LLM01-06) + LLM classifier (Ollama/OpenAI/Anthropic)
- **Audit Chain**: SHA-256 cryptographic chaining — tamper-evident, append-only, `verify-chain` CLI command
- **Event Store**: SQLite (dev) + PostgreSQL (prod) with async non-blocking write queue (<5ms p99 enqueue)
- **LLM Client**: Provider-agnostic abstraction with retry/backoff and graceful degradation
- **Structured Logging**: Loguru JSON output with full event schema on every tool call
- **Risk Auto-Detection**: 6 risk flag types — external_domain, large_payload, sensitive_keyword, high_frequency, unknown_tool, pii_detected

#### REST API
- **10 FastAPI endpoints**: /health, /metrics, /auth/token, /events, /events/{id}, /audit/verify, /audit/export, /policies, /policies/reload, /dashboard
- **JWT Authentication**: HS256 signing, 30-minute expiry, API key exchange
- **RBAC**: 3 roles — admin (all), analyst (read-only), auditor (audit/export)
- **Rate Limiting**: 100 req/min per role, sliding window

#### Observability
- **SIEM Integration**: CEF-formatted webhooks to Splunk HEC, Datadog, Sentinel
- **Prometheus Metrics**: 5 core metrics with labels (events_total, policy_blocks, dlp_detections, injection_detections, latency_seconds)
- **Alert Webhook**: configurable POST on BLOCK/CRITICAL events (Slack, PagerDuty)
- **Grafana Dashboard**: 10-panel JSON template

#### Infrastructure
- **Docker**: Multi-stage python:3.11-slim Dockerfile
- **Docker Compose**: postgres:15 + redis:7 + API + dashboard
- **Alembic**: Database migration framework with initial schema
- **Storage Abstraction**: SQLite/PostgreSQL via DATABASE_URL env var
- **Redis Queue**: Optional Redis-backed event queue for production

#### Policies
- `default.yaml`: 10 enterprise baseline rules
- `finance.yaml`: 5 PCI-DSS/SOX rules
- `healthcare.yaml`: 5 HIPAA rules

#### Demos
- `finance_scenario.py`: 3-agent system (EmailReader → CRM → ResponseWriter)
- `healthcare_scenario.py`: PHI exfiltration protection
- `attack_scenarios.py`: PII_EXFIL, INJECT, UNAUTH enterprise attacks

#### Quality
- 270+ tests with 83%+ coverage
- 100-sample labelled injection corpus with evaluation harness
- OWASP LLM Top 10 coverage map (ATTACK_MATRIX.md)
- Performance SLA: interceptor p99 <50ms, policy eval p99 <5ms, queue enqueue p99 <5ms

### Security
- Fail-open guarantee: interceptor never blocks agent tool calls due to its own errors
- Zero data egress: DLP scanning runs 100% locally via Presidio
- Tamper-evident: SHA-256 audit chain detects any modification to any historical event
- VPC-safe: zero outbound connections when SIEM/alerts not configured

## [0.1.0] — 2026-04-09

### Added
- Initial project scaffold
- GitHub monorepo structure
- CI pipelines (Python + Web)
- Landing page at stridemap.ai
