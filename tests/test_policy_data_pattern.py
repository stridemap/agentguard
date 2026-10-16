"""Policy rules that match a PII entity by name.

Every shipped policy uses these — default.yaml, finance.yaml and healthcare.yaml all
block on US_SSN, CREDIT_CARD or MEDICAL_LICENSE. They were matchable only through a raw
regex over the payload text, which meant they stopped firing as soon as redaction was
enabled: redaction replaces the value before policy runs, so there was nothing left to
match. Two safety features cancelled each other, and the stronger-sounding one disabled
the stricter one.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from agentguard.models import AgentEvent, RiskFlag
from agentguard.policy_engine import PolicyEngine

RULES = """
rules:
  - id: BLOCK-SSN
    name: Block SSN
    priority: 5
    action: BLOCK
    conditions: { tool_name: ".*", data_pattern: "US_SSN" }
  - id: ALLOW-ALL
    name: Allow
    priority: 900
    action: ALLOW
    conditions: {}
"""


@pytest.fixture
def engine(tmp_path):
    path = tmp_path / "p.yaml"
    path.write_text(RULES, encoding="utf-8")
    return PolicyEngine(str(path))


def _event(**over) -> AgentEvent:
    base = {
        "agent_id": "a",
        "session_id": "s",
        "tool_name": "linear.save_issue",
        "run_id": uuid4(),
        "input_str": "",
        "output_str": "",
    }
    return AgentEvent(**{**base, **over})


def test_a_redacted_payload_still_blocks(engine):
    """The case that mattered: redaction had silently disabled the rule."""

    event = _event(
        input_str='{"description": "Employee SSN is [US_SSN]"}',  # value already gone
        dlp_entities=["US_SSN"],
        risk_flags=[RiskFlag.PII_DETECTED],
    )
    assert engine.evaluate(event).result == "BLOCK"


def test_an_unredacted_payload_still_blocks(engine):
    """The regex fallback must keep working for callers that record no entity types."""
    event = _event(input_str='{"description": "SSN 219-09-1122"}')
    assert engine.evaluate(event).result == "BLOCK"


def test_a_different_entity_does_not_match(engine):
    """Matching by name must be exact, or every PII rule becomes every other PII rule."""
    event = _event(
        input_str='{"email": "[EMAIL_ADDRESS]"}',
        dlp_entities=["EMAIL_ADDRESS"],
        risk_flags=[RiskFlag.PII_DETECTED],
    )
    assert engine.evaluate(event).result == "ALLOW"


def test_the_generic_flag_alone_does_not_match(engine):
    """pii_detected says PII was present, never which kind. It must not stand in."""
    event = _event(input_str='{"x": "[REDACTED]"}', risk_flags=[RiskFlag.PII_DETECTED])
    assert engine.evaluate(event).result == "ALLOW"


def test_nothing_sensitive_is_allowed(engine):
    assert engine.evaluate(_event(input_str='{"title": "Hello"}')).result == "ALLOW"


def test_entity_matching_is_case_insensitive(engine):
    event = _event(input_str="{}", dlp_entities=["us_ssn"])
    assert engine.evaluate(event).result == "BLOCK"


@pytest.mark.parametrize("policy", ["default", "finance", "healthcare", "minigate"])
def test_every_shipped_policy_still_loads(policy):
    """These are the files whose entity rules were inert."""
    engine = PolicyEngine(f"policies/{policy}.yaml")
    assert engine.rules, f"{policy}.yaml loaded no rules"
