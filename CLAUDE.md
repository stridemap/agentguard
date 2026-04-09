# AgentGuard — Claude Code Project Context

## What is AgentGuard?

AgentGuard is an open-source Python security library providing governance controls for LLM-powered AI agents. Think **"Palo Alto Prisma, but for AI agents"**. It intercepts tool calls at the LangGraph/LangChain callback layer and enforces security policies including DLP scanning, prompt injection detection, and cryptographic audit logging.

**Owner**: Praveen (Stridemap.ai)
**License**: MIT
**Stage**: Pre-MVP (Sprint 1 of 24-week roadmap)

## Architecture Overview

AgentGuard is an **8-layer governance stack** that sits between AI agents and their tools:

```
Agent (LangGraph/LangChain)
  |
  v
[1] Interceptor Layer (BaseCallbackHandler — on_tool_start / on_tool_end)
  |
  v
[2] Policy Engine (YAML rule evaluation — ALLOW/BLOCK/ALERT/BYPASS)
  |
  v
[3] DLP Scanner (Microsoft Presidio — local PII detection, 15+ entity types)
  |
  v
[4] Injection Detector (Stage 1: regex patterns, Stage 2: LLM classifier)
  |
  v
[5] Event Store (append-only SQLite -> PostgreSQL, SHA-256 audit chain)
  |
  v
[6] Async Queue (asyncio.Queue -> Redis, non-blocking <5ms p99)
  |
  v
[7] REST API (FastAPI + JWT + RBAC)
  |
  v
[8] Dashboard (Streamlit MVP -> Next.js enterprise)
```

## Core Design Principles

1. **Fail-open**: AgentGuard MUST NEVER block an agent's tool call due to its own errors. All interceptor exceptions are caught and logged as WARNINGs — the tool call always proceeds.
2. **Zero-setup developer experience**: `pip install agentguard` + 2 lines of code to integrate. No external services required for MVP (SQLite, local Presidio, local Ollama).
3. **Policy-as-Code**: YAML policy files version-controlled alongside agent code, peer-reviewed like application config.
4. **Non-blocking**: Tool calls cannot wait for DB I/O. Async queue ensures <5ms p99 overhead.
5. **Local-first DLP**: All PII scanning runs locally via Presidio. Zero data sent externally.
6. **Tamper-evident audit**: SHA-256 cryptographic chaining — any modification to any historical event is immediately detectable.

## Monorepo Structure

```
sentinel/                   # Root repository
├── agentguard/             # Python package (core library)
│   ├── __init__.py         # Package init, version
│   ├── interceptor.py      # LangGraph BaseCallbackHandler
│   ├── event_store.py      # SQLite/PostgreSQL event store + audit chain
│   ├── policy_engine.py    # YAML rule evaluation engine
│   ├── dlp_scanner.py      # Microsoft Presidio DLP integration
│   ├── injection_detector.py # Two-stage prompt injection detection
│   ├── llm_client.py       # Provider-agnostic LLM abstraction
│   └── models.py           # Pydantic v2 data models
├── web/                    # Next.js 14 frontend (landing page + enterprise dashboard)
├── dashboard/              # Streamlit real-time trace viewer (MVP)
├── demo/                   # Runnable attack scenario scripts
├── policies/               # YAML policy definitions (default, finance, healthcare)
├── tests/                  # pytest test suite (80% coverage minimum)
├── docs/                   # PDFs: PRD, Architecture, Design, Functional Spec, Test Plan
├── .github/workflows/      # GitHub Actions CI (Python 3.11 + 3.12 matrix)
└── pyproject.toml          # Package config (setuptools, ruff, pytest)
```

## Tech Stack

### Backend (Python)
- **Python**: 3.11+ (3.12 supported)
- **Package manager**: pip + setuptools
- **Key libraries**: LangGraph/LangChain, Pydantic v2, PyYAML, Microsoft Presidio, httpx
- **Testing**: pytest with 80% coverage minimum
- **Linting**: ruff (target py311)
- **Database**: SQLite (MVP) -> PostgreSQL 15 + asyncpg (Sprint 6+)
- **Queue**: asyncio.Queue (MVP) -> Redis (Sprint 6+)
- **API**: FastAPI + Uvicorn + JWT (Sprint 5+)

### Frontend (TypeScript)
- **Framework**: Next.js 14 (App Router)
- **React**: 18.3
- **TypeScript**: 5.4 (strict mode)
- **Styling**: Tailwind CSS (dark theme, teal accent #00D4AA)
- **UI Components**: shadcn/ui (Sprint 11+)

### Dashboard
- **MVP**: Streamlit with auto-refresh (2-second interval)
- **Enterprise**: Next.js + WebSocket real-time feed (Sprint 11+)

### LLM Integration
- **Dev**: Ollama (llama3.2 local)
- **Prod**: OpenAI (gpt-4o-mini) or Anthropic (claude-haiku-4-5-20251001)
- **Selection**: `AGENTGUARD_LLM_PROVIDER` env var (default: ollama)

## Coding Conventions

### Python
- All modules use **type hints** throughout
- Data models use **Pydantic v2** (not v1)
- Async patterns use **asyncio** (not threading, except for DB consumer)
- Docstrings on all public classes and methods
- Logging via **Loguru** with structured JSON output
- Event IDs are **UUID4**, timestamps are **ISO 8601**
- Hashes use **SHA-256** (hashlib)
- Error handling: fail-open pattern — catch exceptions, log WARNING, never raise in interceptor

### Testing
- All tests in `tests/` directory
- Run with: `pytest tests/ --cov=agentguard --cov-fail-under=80`
- Use `conftest.py` for shared fixtures
- Performance tests: assert latency targets (p50 <5ms, p95 <20ms, p99 <50ms for interceptor)
- DLP tests: assert false positive rate <2%
- Injection tests: assert precision >0.90, recall >0.85

### Policy YAML
- Schema validated by Pydantic v2 models
- Actions: `ALLOW`, `BLOCK`, `ALERT`, `BYPASS`
- Severity levels: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`
- Priority: lower number = higher priority (evaluated first)
- Conditions: `tool_name`, `destination_domain`, `data_pattern`, `direction`, `agent_id`

### Git & CI
- CI: GitHub Actions on push to `main` and all PRs
- Python matrix: 3.11 + 3.12
- Lint: `ruff check`
- Test: `pytest` with coverage threshold
- No secrets committed (enforced by CI)
- Branch protection on `main`

## Environment Variables

```bash
OPENAI_API_KEY=              # OpenAI API key (prod injection classifier)
ANTHROPIC_API_KEY=           # Anthropic API key (alternative LLM provider)
DATABASE_URL=                # SQLite path (MVP) or PostgreSQL URL
SECRET_KEY=                  # Application secret
AGENTGUARD_LLM_PROVIDER=    # ollama | openai | anthropic (default: ollama)
AGENTGUARD_LOG_LEVEL=        # DEBUG | INFO | WARN | ERROR
AGENTGUARD_POLICY_PATH=     # Path to policy YAML directory
```

## Sprint Roadmap (Current Phase: MVP)

| Phase | Sprints | Theme | Milestone |
|-------|---------|-------|-----------|
| **MVP** | 1-4 | Foundation, Interceptor, Policy/DLP, Injection/Audit | Demo video + OSS launch |
| **Governance Layer** | 5-8 | FastAPI, PostgreSQL, SIEM, PyPI v1.0 | Production REST API |
| **Pilot Ready** | 9-12 | SSO/RBAC, Kubernetes, Next.js Dashboard | First pilot customer |
| **Production Scale** | 13-16 | Multi-tenant, Policy Marketplace, S3 archival | v2.0-alpha PyPI |
| **Runtime Security** | 17-24 | eBPF, seccomp, process isolation | v2.0 final |

## Key PRD References

- **PRD**: `docs/AgentGuard_PRD_v1.pdf` — Vision, personas, requirements (AM-*, PE-*, DLP-*, PI-*, AC-*)
- **Architecture**: `docs/AgentGuard_System_Architecture_v1.pdf` — 8-layer stack, component interactions
- **System Design**: `docs/AgentGuard_System_Design_v1.pdf` — Data flows, API contracts
- **Functional Spec**: `docs/AgentGuard_Functional_Spec_v1.pdf` — Use cases UC-01 through UC-08
- **Test Plan**: `docs/AgentGuard_Test_Plan_v1.pdf` — Testing strategy per module
- **Sprint Plan**: `docs/AgentGuard_Sprint_Plan_v1.md` — 24-sprint detailed breakdown

## Commands

```bash
# Install Python package (dev mode)
pip install -e ".[dev]"

# Run tests with coverage
pytest tests/ --cov=agentguard --cov-fail-under=80

# Lint
ruff check agentguard/ tests/

# Web frontend
cd web && npm install && npm run dev

# Streamlit dashboard
streamlit run dashboard/app.py
```
