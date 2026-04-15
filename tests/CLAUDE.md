# tests/ — Test Suite

## Overview

pytest test suite for the AgentGuard Python package by [Stridemap Labs LLC](https://stridemap.ai).

**Current status**: 399 tests, 82%+ coverage (v2.0.0)
**Coverage minimum**: 80% (enforced by CI)

## Running Tests

```bash
# Full suite with coverage
pytest tests/ --cov=agentguard --cov-fail-under=80

# Single module
pytest tests/test_interceptor.py -v

# With performance output
pytest tests/ -v --tb=short

# Only fast tests (skip slow LLM classifier tests)
pytest tests/ -m "not slow"
```

## Test File Map

| File | Module | Key Assertions |
|------|--------|----------------|
| `test_interceptor.py` | interceptor.py | 100 calls = 100 events; fail-open on RuntimeError; latency p99 <50ms |
| `test_event_store.py` | event_store.py | Append-only (no UPDATE/DELETE); chain verification; health check |
| `test_policy_engine.py` | policy_engine.py | 10 rule scenarios; hot-reload <2s; priority ordering; <5ms p99 |
| `test_dlp_scanner.py` | dlp_scanner.py | Each PII entity type; FP rate <2%; redaction preserves context |
| `test_injection_detector.py` | injection_detector.py | Precision >0.90; recall >0.85; Stage 1 <5ms; OWASP coverage |
| `test_audit_chain.py` | event_store.py | Tamper detection (zero false negatives); chain break at exact event |
| `test_api.py` | api/main.py | All 10 endpoints; JWT auth; RBAC; rate limiting (Sprint 5+) |

## Conventions

- **conftest.py** for shared fixtures (mock DB, sample events, test policies)
- Use `pytest.fixture` for setup/teardown, not setUp/tearDown classes
- Use `pytest.mark.parametrize` for testing multiple inputs
- Use `pytest.mark.slow` for LLM-dependent tests (network calls)
- Mock external services (Ollama, OpenAI) — never make real API calls in CI
- Use `tmp_path` fixture for temporary SQLite databases
- Assertions should be specific — assert exact values, not just truthiness

## Performance Test Pattern

```python
import time
import statistics

def test_interceptor_latency(interceptor, sample_events):
    """Interceptor overhead must meet latency SLA."""
    times = []
    for event in sample_events:  # 1000 events
        start = time.perf_counter()
        interceptor.process(event)
        times.append((time.perf_counter() - start) * 1000)
    
    sorted_times = sorted(times)
    assert sorted_times[len(times) // 2] < 5      # p50 < 5ms
    assert sorted_times[int(len(times) * 0.95)] < 20  # p95 < 20ms
    assert sorted_times[int(len(times) * 0.99)] < 50  # p99 < 50ms
```

## DLP False Positive Test Pattern

```python
def test_dlp_false_positive_rate(dlp_scanner, non_pii_corpus):
    """False positive rate must be below 2%."""
    false_positives = 0
    for text in non_pii_corpus:  # 50 clean samples
        result = dlp_scanner.scan(text)
        if result.entities_found:
            false_positives += 1
    
    fp_rate = false_positives / len(non_pii_corpus)
    assert fp_rate < 0.02, f"FP rate {fp_rate:.2%} exceeds 2% threshold"
```

## CI Integration

Tests run in GitHub Actions on every push/PR:
- Matrix: Python 3.11 + 3.12
- Coverage uploaded to Codecov
- Coverage threshold: 80% (build fails if below)
- Slow tests (marked `@pytest.mark.slow`) skipped in PR checks, run nightly
