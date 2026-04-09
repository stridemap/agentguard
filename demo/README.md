# demo/ — Attack Scenario Demonstrations

Runnable demo scripts showing AgentGuard protecting AI agents from real-world attack scenarios.

## Scenarios (Planned)

| Scenario | Attack Vector | AgentGuard Defense | OWASP | Sprint |
|----------|--------------|-------------------|-------|--------|
| **PII_EXFIL** | Financial agent emails customer SSN + credit card data | DLP catches PII → Policy BLOCKS | LLM06 | 4 |
| **INJECT** | Contract contains embedded prompt injection | Injection detector flags → quarantine | LLM01 | 4 |
| **UNAUTH** | IT agent calls unauthorized external API | Policy engine → BLOCK (not in allowlist) | LLM08 | 4 |
| **Healthcare** | Agent attempts PHI exfiltration via webhook | DLP + Policy → BLOCK + audit log | LLM06 | 3 |
| **Finance** | 3-agent system (EmailReader → CRM → ResponseWriter) | Full interceptor pipeline tracing | — | 2 |

## Running

```bash
# Run a specific scenario
python -m demo.attack_scenarios

# Run with verbose logging
AGENTGUARD_LOG_LEVEL=DEBUG python -m demo.attack_scenarios
```

## Writing New Scenarios

Each scenario should:
- Map to an OWASP LLM Top 10 category in the docstring
- Use mock agents (no real LLM API calls)
- Write events to a demo-specific SQLite DB
- Print colored terminal output showing attack + defense
- Include `run_scenario()` and `run_all_scenarios()` functions
