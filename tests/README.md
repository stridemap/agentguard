# tests/ — Test Suite

pytest test suite for AgentGuard. Coverage minimum: **80%** (enforced by CI).

## Running

```bash
# Full suite with coverage
pytest tests/ --cov=agentguard --cov-fail-under=80

# Skip slow LLM-dependent tests
pytest tests/ -m "not slow"

# Single module, verbose
pytest tests/test_interceptor.py -v

# With performance timing
pytest tests/ -v --tb=short --durations=10
```

## Test Modules (Planned)

| File | Module Under Test | Key Assertions |
|------|-------------------|----------------|
| `test_interceptor.py` | `interceptor.py` | 100 calls → 100 events; fail-open on error; latency p99 <50ms |
| `test_policy_engine.py` | `policy_engine.py` | 10 rule scenarios; hot-reload; priority ordering; <5ms p99 |
| `test_dlp_scanner.py` | `dlp_scanner.py` | Each PII entity type; FP rate <2%; redaction preserves context |
| `test_injection_detector.py` | `injection_detector.py` | Precision >0.90; recall >0.85; Stage 1 <5ms |
| `test_audit_chain.py` | `event_store.py` | Tamper detection (zero false negatives); chain break at exact event |
| `test_api.py` | `api/main.py` | All endpoints; JWT auth; RBAC; rate limiting (Sprint 5+) |

## Fixtures

Shared fixtures are in `conftest.py`:
- `tmp_db` — temporary SQLite database for test isolation
- `mock_llm` — mock LLM client that returns deterministic responses
- `sample_event` — a pre-built AgentEvent for quick test setup
- `sample_policy_yaml` — temporary YAML policy file with test rules
- `mock_presidio` — mock Presidio analyzer for DLP tests without the dependency

## Conventions

- Use `pytest.fixture` for setup/teardown (not unittest classes)
- Use `pytest.mark.parametrize` for testing multiple inputs
- Use `pytest.mark.slow` for LLM-dependent tests
- Mock external services — never make real API calls in CI
- Assert exact values, not just truthiness
