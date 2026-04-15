# agentguard/ — Python Core Library (v2.0.0)

Part of [AgentGuard](https://stridemap.ai) by Stridemap Labs LLC.

## Overview

This is the main Python package (20+ modules) providing AI agent governance.

## Module Map

| Module | Purpose | Status |
|--------|---------|--------|
| `interceptor.py` | LangGraph BaseCallbackHandler — on_tool_start/end, risk detection, policy/DLP/injection pipeline | Complete |
| `event_store.py` | Append-only SQLite/PostgreSQL store + SHA-256 audit chain + async queue | Complete |
| `policy_engine.py` | YAML policy engine v2 — regex conditions, AND/OR logic, hot-reload | Complete |
| `dlp_scanner.py` | Microsoft Presidio PII detection — 15+ entities, 100% local | Complete |
| `injection_detector.py` | Two-stage detection — 23 regex patterns + LLM classifier | Complete |
| `llm_client.py` | Provider-agnostic LLM abstraction (Ollama/OpenAI/Anthropic/Mock) | Complete |
| `models.py` | Pydantic v2 data models (AgentEvent, InterceptorConfig, RiskFlag, etc.) | Complete |
| `logging.py` | Loguru structured JSON logging | Complete |
| `metrics.py` | Prometheus-compatible metrics (5 core metrics) | Complete |
| `siem.py` | CEF webhook client (Splunk/Datadog) + alert webhooks | Complete |
| `federation.py` | Multi-agent federation, trace sessions, call graphs | Complete |
| `marketplace.py` | Policy pack discovery and installation | Complete |
| `multi_tenant.py` | Multi-tenant organization isolation + billing | Complete |
| `archival.py` | S3/GCS/local audit archival | Complete |
| `compliance/` | SOC2/HIPAA/ISO report generators + data retention | Complete |
| `sdk_adapters.py` | Native OpenAI/Anthropic SDK adapters | Complete |
| `eval_harness.py` | Injection detection evaluation (precision/recall) | Complete |
| `store_factory.py` | SQLite/PostgreSQL storage abstraction factory | Complete |
| `pg_store.py` | PostgreSQL event store backend | Complete |
| `redis_queue.py` | Redis-backed event queue | Complete |

## Coding Rules

- **Pydantic v2** for all data models (not v1, not dataclasses)
- **Type hints** on every function signature and return type
- **Loguru** for structured JSON logging (not stdlib logging)
- **UUID4** for all event IDs
- **ISO 8601** for all timestamps
- **SHA-256** via `hashlib` for all hashing (input_hash, output_hash, event_hash)
- **asyncio.Queue** for non-blocking event writes (tool calls must not wait for DB)

## Fail-Open Pattern (CRITICAL)

Every method in the interceptor pipeline MUST follow this pattern:

```python
def on_tool_start(self, serialized, input_str, *, run_id, parent_run_id, **kwargs):
    try:
        # Policy evaluation, DLP scan, injection detection
        ...
    except Exception as e:
        logger.warning(f"AgentGuard interceptor error (fail-open): {e}")
        # NEVER re-raise — the tool call MUST proceed
```

The agent's tool call is NEVER blocked due to AgentGuard's own errors. Only explicit policy BLOCK decisions prevent tool execution.

## Interceptor Pipeline Order

```
on_tool_start:
  1. Create AgentEvent with metadata (agent_id, tool_name, input_hash, etc.)
  2. Run DLP scan on input text
  3. Run injection detection on input text
  4. Evaluate policy engine (conditions include DLP + injection results)
  5. If policy result = BLOCK → raise AgentGuardBlockException
  6. Enqueue event to async write queue

on_tool_end:
  1. Record output_hash, latency_ms
  2. Run DLP scan on output text
  3. Auto-flag risks (external_domain, large_payload, sensitive_keyword, high_frequency)
  4. Enqueue completed event to async write queue
```

## Performance Targets

| Operation | p50 | p95 | p99 |
|-----------|-----|-----|-----|
| Interceptor overhead | <5ms | <20ms | <50ms |
| Policy evaluation | <1ms | <3ms | <5ms |
| DLP scan (10KB) | - | - | <50ms |
| Queue write | - | - | <5ms |
| Regex injection scan (1KB) | - | - | <5ms |

## Dependencies (to be added to pyproject.toml)

```
langchain-core          # BaseCallbackHandler
langgraph               # Agent framework integration
pydantic>=2.0           # Data models
pyyaml                  # Policy YAML parsing
presidio-analyzer       # DLP PII detection
presidio-anonymizer     # DLP PII redaction
loguru                  # Structured logging
httpx                   # Async HTTP (LLM client)
```
