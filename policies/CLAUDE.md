# policies/ — YAML Policy Definitions

## Overview

Policy-as-Code definitions for AgentGuard's rule engine. Each YAML file contains a list of rules that govern agent tool-call behavior. These files are version-controlled alongside agent code and peer-reviewed like application config.

## Policy Files

| File | Purpose | Sprint |
|------|---------|--------|
| `default.yaml` | 10 enterprise baseline rules (apply to all environments) | 3 |
| `finance.yaml` | Financial sector rules (PCI-DSS, SOX compliance) | 3 |
| `healthcare.yaml` | Healthcare/HIPAA rules (PHI protection) | 3 |

## Rule Schema

```yaml
rules:
  - id: "block_ssn_exfiltration"           # Unique identifier
    name: "Block SSN Exfiltration"          # Human-readable name
    description: "Block any tool call that attempts to send SSN data externally"
    priority: 10                             # Lower number = higher priority
    conditions:
      tool_name: "send_email|post_webhook"  # String, regex, or list
      destination_domain: "!internal.com"    # String, list, or null (! = NOT)
      data_pattern: "US_SSN"                # PII entity type from Presidio
      direction: "output"                    # input | output | both
      agent_id: null                         # String or null (null = all agents)
    action: "BLOCK"                          # ALLOW | BLOCK | ALERT | BYPASS
    alert_severity: "CRITICAL"              # LOW | MEDIUM | HIGH | CRITICAL
```

## Actions

| Action | Behavior |
|--------|----------|
| `ALLOW` | Tool call proceeds normally, event logged |
| `BLOCK` | Tool call denied, AgentGuardBlockException raised (caught by fail-open wrapper), event logged with BLOCKED status |
| `ALERT` | Tool call proceeds, alert sent to SIEM/webhook, event logged with alert severity |
| `BYPASS` | Tool call proceeds, AgentGuard skips all further scanning (for trusted internal tools) |

## Default Rules (10 Enterprise Baseline)

1. `block_external_email_with_pii` — Block sending PII to external email domains
2. `alert_large_payload` — Alert when tool output exceeds 10KB
3. `block_unauthorized_api` — Block calls to APIs not in the approved allowlist
4. `allow_internal_tools` — Allow all calls to internal/trusted tool endpoints
5. `block_ssn_exfiltration` — Block SSN data in any outbound direction
6. `alert_high_frequency` — Alert when agent exceeds 10 tool calls per minute
7. `block_unknown_destinations` — Block tool calls to unrecognized external domains
8. `allow_crm_lookup` — Allow CRM read operations for authorized agents
9. `alert_credential_keywords` — Alert on keywords: password, secret, token, api_key
10. `block_phi_transmission` — Block PHI (medical data) from leaving the system

## Evaluation Rules

- Rules are evaluated in **priority order** (lower number first)
- **First match wins** — once a rule matches, no further rules are evaluated
- If no rule matches, the default action is **ALLOW** (fail-open)
- Conditions use AND logic — all non-null conditions must match
- Hot-reload: policy files are watched for changes and reloaded within 2 seconds without restart

## Validation

All YAML files are validated against Pydantic v2 models at load time. Invalid YAML raises `PolicyValidationError` with a helpful message indicating the specific validation failure.
