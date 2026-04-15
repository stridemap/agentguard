# AgentGuard — Test Plan

A product by [Stridemap Labs LLC](https://stridemap.ai) — AI Security for the Enterprise.

## Overview

This document defines the testing strategy, coverage targets, and acceptance criteria for each AgentGuard module. Tests are written using `pytest` and live in the `tests/` directory.

**Current status**: 399 tests, 82%+ coverage (v2.0.0)
**Coverage gate**: 80% minimum (enforced by CI via `--cov-fail-under=80`)

---

## Module Test Matrix

### 1. Interceptor (`test_interceptor.py`) — Sprint 2

| Test Case | Type | Acceptance Criteria |
|-----------|------|-------------------|
| 100 consecutive tool calls → 100 events in DB | Functional | Zero events dropped |
| Interceptor throws RuntimeError → tool call completes | Fail-open | WARNING event in log, tool call succeeds |
| Latency overhead over 1,000 calls | Performance | p50 <5ms, p95 <20ms, p99 <50ms |
| Risk auto-flagging: external_domain | Functional | Correct flag on external URLs |
| Risk auto-flagging: large_payload (>10KB) | Functional | Correct flag on oversized output |
| Risk auto-flagging: high_frequency (>10 calls/min) | Functional | Correct flag on burst traffic |
| Structured event contains all required fields | Schema | UUID4 event_id, ISO 8601 timestamp, SHA-256 hashes |
| Queue depth stable under 100 events/sec | Performance | No unbounded growth |

### 2. Event Store (`test_event_store.py`) — Sprint 2

| Test Case | Type | Acceptance Criteria |
|-----------|------|-------------------|
| Append event and retrieve by ID | Functional | Exact field match |
| UPDATE/DELETE operations rejected | Security | Raises error or silently ignores |
| verify_chain() on valid chain | Functional | Returns `is_valid=True` |
| verify_chain() detects single-byte modification | Security | Returns `is_valid=False`, identifies tampered event |
| Genesis event has prev_hash of all zeros | Schema | `prev_hash == '0' * 64` |
| health_check() returns status dict | Functional | Contains db_connection, queue_depth, events_per_second |

### 3. Policy Engine (`test_policy_engine.py`) — Sprint 3

| Test Case | Type | Acceptance Criteria |
|-----------|------|-------------------|
| 10 default rules each with ALLOW and BLOCK outcomes | Functional | Correct decision per rule |
| Hot-reload: modify YAML → new rule applied | Functional | Applied within 2 seconds without restart |
| Invalid YAML raises PolicyValidationError | Error handling | Helpful error message |
| Priority ordering: lower number wins | Functional | First-match by priority |
| 1,000 evaluations in <5 seconds | Performance | Total wall time <5s |
| Empty conditions match all events | Functional | Null conditions = wildcard |
| No rule matches → default ALLOW | Fail-open | Returns ALLOW decision |

### 4. DLP Scanner (`test_dlp_scanner.py`) — Sprint 3

| Test Case | Type | Acceptance Criteria |
|-----------|------|-------------------|
| Detect SSN (123-45-6789) | Functional | Entity type = US_SSN |
| Detect credit card (4111-1111-1111-1111) | Functional | Entity type = CREDIT_CARD |
| Detect email address | Functional | Entity type = EMAIL_ADDRESS |
| Detect phone number | Functional | Entity type = PHONE_NUMBER |
| Detect medical license | Functional | Entity type = MEDICAL_LICENSE |
| False positive rate on 50 clean samples | Quality | FP rate <2% |
| Redaction preserves surrounding text | Functional | PII replaced with `[ENTITY_TYPE]` |
| Below-threshold entities not flagged | Functional | Confidence <0.85 → not reported |
| Scan latency for 10KB payload | Performance | <50ms |
| Sensitivity levels (LOW/MEDIUM/HIGH) | Configuration | Correct entity scope per level |

### 5. Injection Detector (`test_injection_detector.py`) — Sprint 4

| Test Case | Type | Acceptance Criteria |
|-----------|------|-------------------|
| "Ignore previous instructions" → INJECTED | Functional | Stage 1 regex match |
| "Disregard your training" → INJECTED | Functional | Stage 1 regex match |
| Base64-encoded injection → SUSPICIOUS | Functional | Stage 1 detects encoded payload |
| Clean business text → CLEAN | Functional | No false positive |
| Precision on 100-sample labelled corpus | Quality | >0.90 |
| Recall on 100-sample labelled corpus | Quality | >0.85 |
| Stage 1 regex latency for 1KB input | Performance | <5ms p99 |
| Sensitivity LOW → Stage 1 only | Configuration | Stage 2 never called |
| Sensitivity HIGH → both stages always | Configuration | Stage 2 called even on CLEAN |
| LLM unavailable → returns SUSPICIOUS with warning | Graceful degradation | No crash, warning logged |

### 6. Audit Chain (`test_audit_chain.py`) — Sprint 4

| Test Case | Type | Acceptance Criteria |
|-----------|------|-------------------|
| 100 events → valid chain | Functional | verify_chain() returns True |
| Modify event_id of event #50 → chain breaks at #50 | Tamper detection | first_tampered_event_id = event #50 |
| Modify timestamp of event #1 → chain breaks at #1 | Tamper detection | Detected at genesis event |
| Delete event from middle → chain breaks | Tamper detection | Gap detected |
| CLI `verify-chain` command output | Integration | Prints valid/invalid with event count |
| Verification latency for 10,000 events | Performance | <5 seconds |

---

## Test Infrastructure

### Fixtures (conftest.py)

- `tmp_db` — temporary SQLite database
- `mock_llm` — deterministic LLM responses
- `sample_event` / `sample_event_blocked` — pre-built events
- `sample_policy_yaml` — temporary YAML policy file
- `mock_presidio` — mock Presidio analyzer
- `pii_samples` — dict of PII text samples
- `assert_latency` — helper for percentile assertions

### Markers

- `@pytest.mark.slow` — requires LLM calls or heavy I/O
- `@pytest.mark.integration` — requires external services
- `@pytest.mark.performance` — benchmark tests

### CI Pipeline

```yaml
# python-ci.yml
- black --check agentguard/ tests/
- ruff check agentguard/ tests/
- pytest tests/ --cov=agentguard --cov-fail-under=80 -m "not slow"
```

---

## OWASP LLM Top 10 Coverage Target

| OWASP ID | Category | Test Coverage | Target |
|----------|----------|--------------|--------|
| LLM01 | Prompt Injection | `test_injection_detector.py` | >80% |
| LLM02 | Insecure Output Handling | `test_dlp_scanner.py` | >80% |
| LLM04 | Model Denial of Service | `test_interceptor.py` (high_frequency) | >60% |
| LLM06 | Sensitive Info Disclosure | `test_dlp_scanner.py` | >90% |
| LLM07 | Insecure Plugin Design | `test_policy_engine.py` | >80% |
| LLM08 | Excessive Agency | `test_policy_engine.py` (BLOCK rules) | >80% |

---

## Quality Gates

| Gate | Threshold | Enforcement |
|------|-----------|-------------|
| Code coverage | ≥80% | CI (`--cov-fail-under=80`) |
| Injection precision | ≥0.90 | Sprint 4 acceptance criteria |
| Injection recall | ≥0.85 | Sprint 4 acceptance criteria |
| DLP false positive rate | <2% | Sprint 3 acceptance criteria |
| Interceptor p99 latency | <50ms | Performance test assertions |
| Policy evaluation p99 | <5ms | Performance test assertions |
| Audit chain tamper detection | 0 false negatives | Sprint 4 acceptance criteria |
