# AgentGuard — OWASP LLM Top 10 Attack Coverage Matrix

Maps each OWASP LLM category to AgentGuard modules, test coverage, and demo scenarios.

## Coverage Summary

| OWASP ID | Category | AgentGuard Module | Coverage | Demo Scenario |
|----------|----------|-------------------|----------|---------------|
| LLM01 | Prompt Injection | `injection_detector.py` (21 regex + LLM Stage 2) | >80% | INJECT |
| LLM02 | Insecure Output Handling | `dlp_scanner.py` (output scanning) + `policy_engine.py` | >80% | PII_EXFIL |
| LLM03 | Training Data Poisoning | N/A (model layer — out of scope) | — | — |
| LLM04 | Model Denial of Service | `interceptor.py` (high_frequency risk flag) | >60% | — |
| LLM05 | Supply Chain Vulnerabilities | N/A (dependency layer — out of scope) | — | — |
| LLM06 | Sensitive Info Disclosure | `dlp_scanner.py` (15+ PII types) + `policy_engine.py` | >90% | PII_EXFIL, Healthcare |
| LLM07 | Insecure Plugin Design | `policy_engine.py` (tool allowlisting) | >80% | UNAUTH |
| LLM08 | Excessive Agency | `policy_engine.py` (BLOCK unauthorized tools) + `interceptor.py` (unknown_tool flag) | >80% | UNAUTH |
| LLM09 | Overreliance | N/A (UX layer — out of scope) | — | — |
| LLM10 | Model Theft | N/A (model layer — out of scope) | — | — |

## Detection Patterns by OWASP Category

### LLM01 — Prompt Injection (21 patterns)

| Pattern Name | Type | Severity |
|-------------|------|----------|
| ignore_previous | Direct | INJECTED |
| disregard_training | Direct | INJECTED |
| forget_everything | Direct | INJECTED |
| dan_pattern | Direct | INJECTED |
| new_instructions | Direct | INJECTED |
| system_prompt_override | Direct | INJECTED |
| bypass_safety | Direct | INJECTED |
| pretend_admin | Role manipulation | INJECTED |
| unrestricted_mode | Role manipulation | INJECTED |
| instruction_delimiter | Separator | INJECTED |
| html_comment_injection | Indirect | INJECTED |
| markdown_injection | Indirect | INJECTED |
| you_are_now | Direct | SUSPICIOUS |
| act_as | Direct | SUSPICIOUS |
| base64_instruction | Indirect | SUSPICIOUS |
| hidden_instruction | Indirect | SUSPICIOUS |
| separator_injection | Separator | SUSPICIOUS |

### LLM02 — Insecure Output Handling

| Defense | Module |
|---------|--------|
| DLP scan on tool output | `dlp_scanner.py` |
| PII redaction | `dlp_scanner.py` (redact mode) |
| Output regex policy | `policy_engine.py` (output_regex condition) |

### LLM06 — Sensitive Information Disclosure

| Entity Type | Presidio Recognizer |
|------------|-------------------|
| US_SSN | PatternRecognizer |
| CREDIT_CARD | PatternRecognizer |
| EMAIL_ADDRESS | PatternRecognizer |
| PHONE_NUMBER | PatternRecognizer |
| PERSON | SpacyRecognizer |
| MEDICAL_LICENSE | PatternRecognizer |
| IP_ADDRESS | PatternRecognizer |
| URL | PatternRecognizer |
| US_BANK_NUMBER | PatternRecognizer |
| IBAN_CODE | PatternRecognizer |

### LLM08 — Excessive Agency

| Defense | Module |
|---------|--------|
| Tool allowlisting | `interceptor.py` (known_tools config) |
| Unknown tool flag | `interceptor.py` (UNKNOWN_TOOL risk flag) |
| Domain allowlisting | `interceptor.py` (internal_domains config) |
| Policy BLOCK on unauthorized | `policy_engine.py` |

## Evaluation Corpus

- **Location**: `tests/corpus/injection_corpus.json`
- **Size**: 100 labelled samples
- **Distribution**: 25 INJECTED, 15 SUSPICIOUS, 60 CLEAN
- **Quality gate**: Precision >= 0.90, Recall >= 0.85
