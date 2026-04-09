# AgentGuard

[![CI](https://github.com/stridemap/agentguard/actions/workflows/ci.yml/badge.svg)](https://github.com/stridemap/agentguard/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Guardrails and policy enforcement for AI agents.**

Think Palo Alto Prisma, but for AI agents. AgentGuard intercepts every tool call your LLM-powered agents make and enforces security policies — DLP scanning, prompt injection detection, and tamper-proof audit logging — without changing a single line of your agent code.

## Quickstart

```bash
pip install agentguard
```

```python
from agentguard import AgentGuardInterceptor

# Wrap any LangGraph/LangChain agent — zero code changes needed
config = {"callbacks": [AgentGuardInterceptor()]}
agent.invoke(input, config=config)
```

## Architecture

```
Agent (LangGraph / LangChain)
  │
  ▼
┌─────────────────────────────────────────┐
│  AgentGuard Governance Layer            │
│                                         │
│  ┌───────────┐  ┌──────────────────┐    │
│  │ Intercept │→ │ Policy Engine    │    │
│  │ Tool Call │  │ (YAML rules)     │    │
│  └───────────┘  └──────────────────┘    │
│        │              │                 │
│        ▼              ▼                 │
│  ┌───────────┐  ┌──────────────────┐    │
│  │ DLP Scan  │  │ Injection Detect │    │
│  │ (Presidio)│  │ (Regex + LLM)    │    │
│  └───────────┘  └──────────────────┘    │
│        │              │                 │
│        ▼              ▼                 │
│  ┌──────────────────────────────────┐   │
│  │ Append-Only Audit Chain (SHA-256)│   │
│  └──────────────────────────────────┘   │
└─────────────────────────────────────────┘
  │
  ▼
Tool Execution
```

## Features

| Module | What it does |
|--------|-------------|
| **Interceptor** | LangGraph `BaseCallbackHandler` — logs every tool call with zero agent code changes |
| **Policy Engine** | YAML-based rules with ALLOW / BLOCK / ALERT / BYPASS actions |
| **DLP Scanner** | Microsoft Presidio PII detection — 15+ entity types, 100% local, zero data egress |
| **Injection Detector** | Two-stage defense: fast regex patterns + LLM classifier for edge cases |
| **Audit Chain** | SHA-256 cryptographic chaining — tamper-evident, SOC2/HIPAA-ready |

## Project Structure

```
agentguard/     Python package (core library)
web/            Next.js 14 frontend (landing page + enterprise dashboard)
dashboard/      Streamlit real-time trace viewer
demo/           Runnable attack scenario scripts
policies/       YAML policy definitions
tests/          pytest test suite (80% coverage minimum)
docs/           PRD, architecture, design, and test plan documents
```

## Development

```bash
# Python — install in dev mode
pip install -e ".[dev]"

# Lint
ruff check agentguard/ tests/

# Test with coverage
pytest tests/ --cov=agentguard --cov-fail-under=80

# Web frontend
cd web && npm install && npm run dev
```

## License

[MIT](LICENSE)
