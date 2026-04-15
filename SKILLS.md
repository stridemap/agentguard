# AgentGuard — Claude Code Skills Reference

A product by [Stridemap Labs LLC](https://stridemap.ai) — AI Security for the Enterprise.

This document defines reusable Claude Code workflows for common development tasks in the AgentGuard project (v2.0.0, 399 tests, 20+ modules).

---

## Skill: Implement a New Module

When implementing a new AgentGuard Python module (e.g., interceptor, policy_engine, dlp_scanner):

1. **Read the relevant PRD section** from `docs/` before writing any code
2. **Read the sprint plan** section for the module in `docs/AgentGuard_Sprint_Plan_v1.md`
3. **Create the module** in `agentguard/` with:
   - Full type hints on all functions and methods
   - Pydantic v2 models for all data structures
   - Docstrings on all public classes and methods
   - Fail-open error handling (catch exceptions, log WARNING, never crash the agent)
4. **Create corresponding tests** in `tests/test_<module>.py` with:
   - Happy path tests for each public method
   - Edge case and error handling tests
   - Performance assertions where specified (latency targets in sprint plan)
   - Coverage must stay above 80%
5. **Run lint and tests**: `ruff check agentguard/ tests/ && pytest tests/ --cov=agentguard --cov-fail-under=80`
6. **Update `agentguard/__init__.py`** to export new public classes

---

## Skill: Add a Policy Rule

When adding a new YAML policy rule:

1. Open the target policy file in `policies/` (default.yaml, finance.yaml, or healthcare.yaml)
2. Add a new rule following this schema:
   ```yaml
   - id: "rule_unique_id"
     name: "Human-Readable Rule Name"
     description: "What this rule does and why"
     priority: 100          # Lower = higher priority
     conditions:
       tool_name: "tool_pattern"        # string, regex, or list
       destination_domain: null          # string, list, or null
       data_pattern: null                # PII entity type or null
       direction: "both"                 # input | output | both
       agent_id: null                    # string or null
     action: "BLOCK"                     # ALLOW | BLOCK | ALERT | BYPASS
     alert_severity: "HIGH"             # LOW | MEDIUM | HIGH | CRITICAL
   ```
3. Add a corresponding test case in `tests/test_policy_engine.py`
4. Verify the rule evaluates correctly: `pytest tests/test_policy_engine.py -v`

---

## Skill: Add a Demo Scenario

When creating a new attack/demo scenario:

1. Create a new file in `demo/` named descriptively (e.g., `healthcare_scenario.py`, `attack_scenarios.py`)
2. Structure the scenario with:
   - Clear docstring explaining the attack vector being demonstrated
   - Realistic mock agents with 2-3 tool calls each
   - AgentGuard interceptor wired in via `config = {'callbacks': [AgentGuardInterceptor()]}`
   - Colored terminal output (use `rich` or ANSI codes) showing attack attempt and AgentGuard response
   - Events written to a demo SQLite database
   - A `run_scenario()` function for standalone execution
   - A `run_all_scenarios()` function if multiple scenarios exist in one file
3. Map the scenario to OWASP LLM Top 10 categories (LLM01-LLM10)
4. Test the scenario runs without errors: `python -m demo.<scenario_name>`

---

## Skill: Create a Streamlit Dashboard Page

When adding features to the Streamlit dashboard:

1. Edit `dashboard/app.py`
2. Follow these patterns:
   - Auto-refresh: `time.sleep(2)` + `st.rerun()` for live updates
   - Risk color coding: green=CLEAN, yellow=SUSPICIOUS, red=BLOCKED/HIGH_RISK
   - Sidebar for filters (agent_id, tool_name, risk_flag, time range)
   - `st.metric` cards at top for summary KPIs
   - `st.expander` for event detail views
   - `st.dataframe` for event tables (paginated, max 100 rows)
3. Performance target: dashboard must load in <3 seconds with 10,000 events

---

## Skill: Add a FastAPI Endpoint (Sprint 5+)

When adding a new REST API endpoint:

1. Add the route in `api/main.py`
2. Create Pydantic request/response models
3. Apply JWT authentication decorator (except `/health` and `/metrics`)
4. Apply RBAC role check (admin, analyst, auditor)
5. Add structured error response: `{"error": "...", "message": "...", "trace_id": "..."}`
6. Write integration test using `httpx.AsyncClient` + `TestClient`
7. Update OpenAPI docs description
8. Verify: `pytest tests/test_api.py -v`

---

## Skill: Sprint Workflow

Daily development workflow following the sprint plan:

### Morning (Learning Deep Dive)
1. Read the sprint's Learning Deep Dive section in `docs/AgentGuard_Sprint_Plan_v1.md`
2. Review the relevant PRD/Architecture/Design PDF sections
3. Note key concepts and interview talking points

### Session 1 (Core Implementation)
1. Read the Claude Code Session Guide prompt for the current sprint/session
2. Implement the specified module or feature
3. Write code following the conventions in root `CLAUDE.md`
4. Commit frequently with descriptive messages

### Session 2 (Tests, Integration, Polish)
1. Write tests for the day's implementation
2. Run full test suite: `pytest tests/ --cov=agentguard --cov-fail-under=80`
3. Run linter: `ruff check agentguard/ tests/`
4. Integrate with existing modules (wire into interceptor pipeline)
5. Update demo scenarios if applicable

### End of Day
1. Commit all code
2. Update Linear tickets (use Linear MCP if available)
3. Note 3 interview talking points from the sprint plan

---

## Skill: Performance Validation

When validating performance targets:

1. **Interceptor latency**: p50 <5ms, p95 <20ms, p99 <50ms
   ```python
   import time
   times = []
   for _ in range(1000):
       start = time.perf_counter()
       # run interceptor
       times.append((time.perf_counter() - start) * 1000)
   assert sorted(times)[499] < 5    # p50
   assert sorted(times)[949] < 20   # p95
   assert sorted(times)[989] < 50   # p99
   ```

2. **Policy evaluation**: <5ms p99, 1000 evaluations in <5 seconds total
3. **DLP scan**: <50ms for 10KB payload
4. **Queue write**: <5ms p99 (non-blocking)
5. **Dashboard load**: <3 seconds with 10,000 events
6. **DLP false positive rate**: <2% on synthetic non-PII corpus
7. **Injection detection**: precision >0.90, recall >0.85 on labelled corpus

---

## Skill: CI Pipeline Validation

Before pushing code, verify locally:

```bash
# Python lint
ruff check agentguard/ tests/

# Python tests with coverage
pytest tests/ --cov=agentguard --cov-fail-under=80

# Web lint + build (if web/ changed)
cd web && npm run lint && npm run build

# Check for secrets
git diff --cached | grep -iE "(api_key|secret|password|token)" && echo "WARNING: Possible secret detected"
```

---

## Skill: OWASP LLM Mapping

When implementing security features, map to OWASP LLM Top 10:

| OWASP ID | Category | AgentGuard Module | Sprint |
|----------|----------|-------------------|--------|
| LLM01 | Prompt Injection | injection_detector.py (Stage 1 regex + Stage 2 LLM) | 4 |
| LLM02 | Insecure Output Handling | dlp_scanner.py (output scanning) | 3 |
| LLM03 | Training Data Poisoning | N/A (out of scope — model layer) | - |
| LLM04 | Model Denial of Service | interceptor.py (high_frequency risk flag) | 2 |
| LLM05 | Supply Chain Vulnerabilities | N/A (out of scope — dependency layer) | - |
| LLM06 | Sensitive Info Disclosure | dlp_scanner.py (PII detection + redaction) | 3 |
| LLM07 | Insecure Plugin Design | policy_engine.py (tool allowlisting) | 3 |
| LLM08 | Excessive Agency | policy_engine.py (BLOCK unauthorized tools) | 3 |
| LLM09 | Overreliance | N/A (out of scope — UX layer) | - |
| LLM10 | Model Theft | N/A (out of scope — model layer) | - |
