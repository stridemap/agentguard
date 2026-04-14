# Changelog

All notable changes to AgentGuard are documented here.

## [2.0.0] — 2026-04-13

### Added — Production Scale (Sprints 13-16)

#### Multi-Agent Federation
- **FederationManager**: agent registry, distributed trace sessions (W3C TraceContext-inspired), handoff tracking, directed call graphs
- **Federation policies**: inter-agent rules with wildcards and tool conditions
- **12 API endpoints**: `/federation/agents`, `/federation/sessions`, `/federation/rules`, etc.

#### Policy Marketplace
- **5 community policy packs**: finance/pci_dss, finance/sox, healthcare/hipaa, legal/privilege, it/security_ops
- **PolicyMarketplace**: discover, search, preview, and install packs
- **5 API endpoints**: `/marketplace/packs`, `/marketplace/search`, `/marketplace/install`

#### S3 Audit Archival
- **AuditArchiver**: nightly export to S3 (AES256), GCS, or local filesystem
- Archive includes events + chain verification result as JSON

#### Multi-Tenant SaaS
- **TenantManager**: create/suspend/delete organizations
- **Tenant isolation**: separate SQLite DB per tenant
- **Billing metadata**: event_count, api_calls, storage_bytes per period
- **10 API endpoints**: `/tenants/*` for full lifecycle management

#### SDK Adapters
- **govern_tool_call()**: universal wrapper for any agent framework
- **govern_openai_tool()**: native OpenAI Agents SDK adapter
- **govern_anthropic_tool()**: native Anthropic Claude SDK adapter
- **GovernedToolRunner**: reusable wrapper class

#### Performance Hardening
- **Locust load test**: sustained 500 events/sec configuration
- **Performance gate tests**: enforced SLAs on every release (interceptor p50/p95/p99, policy p99, queue p99, injection Stage 1 p99, store append p99, throughput 500/sec)

#### Documentation
- **COMPATIBILITY.md**: integration guides for 6 agent frameworks
- **MIGRATION.md**: v1.5 → v2.0 upgrade guide (no breaking changes)

### Changed
- Version bumped to 2.0.0
- 391+ tests, 84%+ coverage

---

## [1.5.0] — 2026-04-13

### Added — Pilot Ready (Sprints 9-12)

#### Enterprise Authentication
- **OIDC/OAuth 2.0 SSO**: Okta, Azure AD, Google Workspace via authlib
- **SAML 2.0 SP**: Stub implementation for enterprise IdP integration
- **Refresh tokens**: Redis-backed session management (7-day TTL)
- **Row-level RBAC**: Tenant isolation — users see only assigned agent events

#### Next.js Enterprise Dashboard
- **Live Feed** (`/dashboard`): Recharts visualizations, 4 metric cards, auto-refresh, risk colour coding, event detail panel
- **Audit Chain** (`/dashboard/audit`): One-click verify, tampered event display
- **Policy Manager** (`/dashboard/policies`): Rule list with action badges, one-click reload
- **Compliance Reports** (`/dashboard/reports`): SOC2 CC6, HIPAA §164.312, ISO 27001 A.12.4 exports
- **Settings** (`/dashboard/settings`): API auth, connection status
- **RBAC-gated sidebar**: Admin sees all, Analyst/Auditor/Viewer restricted

#### Compliance Reports (auto-populated)
- **SOC2 CC6**: CC6.1 (access security), CC6.6 (system boundaries), CC6.8 (unauthorized access)
- **HIPAA §164.312**: §164.312(a)-(e) technical safeguards evidence pack
- **ISO 27001 A.12.4**: A.12.4.1-4 logging and monitoring controls
- **Compliance API**: `/compliance/soc2`, `/compliance/hipaa`, `/compliance/iso27001`

#### Data Retention
- Configurable retention periods: 30/90/365 days per regulation
- `/compliance/retention/status` and `/compliance/retention/enforce` endpoints
- Dry-run mode for safe preview before purging

#### Infrastructure
- **Kubernetes Helm chart**: API + worker + dashboard deployments, HPA, ingress, secrets
- **Docker**: Multi-stage python:3.11-slim, non-root user, HEALTHCHECK
- **GHCR publishing**: GitHub Actions workflow on tag/release
- **K8s smoke test**: 9-check bash script

#### Pilot Onboarding
- **ONBOARDING.md**: 5-minute setup guide (pip, Docker Compose, Helm)
- Configuration reference table
- Compliance report generation instructions

### Changed
- Version bumped to 1.5.0
- Policy Engine v2: regex conditions (input_regex, output_regex) + AND/OR match modes
- Dashboard upgraded from Streamlit MVP to Next.js 14 + Recharts

---

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
