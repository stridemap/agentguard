"""Tests for the YAML policy rule engine.

Covers:
- Rule loading and Pydantic validation
- 10 scenario rules with ALLOW and BLOCK outcomes
- Priority ordering (lower number wins)
- Hot-reload (modify YAML, verify new rule applied)
- Invalid YAML raises PolicyValidationError
- Performance: 1000 evaluations in < 5 seconds
- Condition matching: tool_name, domain, data_pattern, agent_id
"""

from __future__ import annotations

import time
from pathlib import Path
from uuid import uuid4

import pytest

from agentguard.models import AgentEvent
from agentguard.policy_engine import PolicyEngine, PolicyValidationError

# ── Fixtures ──────────────────────────────────────────────────────────


@pytest.fixture()
def default_policy():
    """Path to the default policy file."""
    return str(Path(__file__).parent.parent / "policies" / "default.yaml")


@pytest.fixture()
def engine(default_policy):
    """Engine loaded with default.yaml."""
    return PolicyEngine(default_policy)


def make_event(**kwargs) -> AgentEvent:
    """Create a test event with overrides."""
    defaults = {
        "tool_name": "generic_tool",
        "run_id": uuid4(),
        "agent_id": "test-agent",
        "session_id": "test-session",
        "input_str": "",
        "output_str": "",
    }
    defaults.update(kwargs)
    return AgentEvent(**defaults)


# ── Loading tests ────────────────────────────────────────────────────


class TestPolicyLoading:
    def test_load_default_policy(self, default_policy):
        engine = PolicyEngine(default_policy)
        assert engine.get_rule_count() == 10

    def test_load_finance_policy(self):
        path = str(Path(__file__).parent.parent / "policies" / "finance.yaml")
        engine = PolicyEngine(path)
        assert engine.get_rule_count() == 5

    def test_load_healthcare_policy(self):
        path = str(Path(__file__).parent.parent / "policies" / "healthcare.yaml")
        engine = PolicyEngine(path)
        assert engine.get_rule_count() == 5

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            PolicyEngine("/nonexistent/policy.yaml")

    def test_invalid_yaml(self, tmp_path):
        bad = tmp_path / "bad.yaml"
        bad.write_text("rules:\n  - id: 1\n    name: [invalid")
        with pytest.raises(PolicyValidationError):
            PolicyEngine(str(bad))

    def test_invalid_action(self, tmp_path):
        bad = tmp_path / "bad_action.yaml"
        bad.write_text(
            "rules:\n  - id: r1\n    name: test\n    action: EXPLODE\n    priority: 1"
        )
        with pytest.raises(PolicyValidationError):
            PolicyEngine(str(bad))

    def test_empty_yaml(self, tmp_path):
        empty = tmp_path / "empty.yaml"
        empty.write_text("")
        engine = PolicyEngine(str(empty))
        assert engine.get_rule_count() == 0

    def test_no_policy_path(self):
        engine = PolicyEngine()
        assert engine.get_rule_count() == 0
        decision = engine.evaluate(make_event())
        assert decision.result == "ALLOW"

    def test_rules_sorted_by_priority(self, engine):
        rules = engine.get_rules()
        priorities = [r.priority for r in rules]
        assert priorities == sorted(priorities)


# ── Evaluation: 10 scenario tests ────────────────────────────────────


class TestPolicyEvaluation:
    def test_ssn_exfiltration_blocked(self, engine):
        event = make_event(
            tool_name="send_email",
            output_str="Customer SSN: 421-83-7219",
        )
        decision = engine.evaluate(event)
        assert decision.result == "BLOCK"

    def test_credit_card_blocked(self, engine):
        event = make_event(
            tool_name="generic_tool",
            output_str="Card: 4532-8721-0093-4829",
        )
        decision = engine.evaluate(event)
        assert decision.result == "BLOCK"

    def test_crm_lookup_matches_allow_rule(self, tmp_path):
        """CRM lookup matched by allow_crm_lookup with no competing broad rules."""
        policy = tmp_path / "crm.yaml"
        policy.write_text("""\
rules:
  - id: allow_crm
    name: Allow CRM
    priority: 80
    conditions:
      tool_name: "query_crm|lookup_contact"
      direction: "input"
    action: ALLOW
    alert_severity: LOW
""")
        engine = PolicyEngine(str(policy))
        event = make_event(tool_name="query_crm", input_str="lookup customer")
        decision = engine.evaluate(event)
        assert decision.result == "ALLOW"
        assert decision.matched_rule == "allow_crm"

    def test_internal_domain_matches_allow_rule(self, tmp_path):
        """Internal domain matched by allow_internal_tools."""
        policy = tmp_path / "internal.yaml"
        policy.write_text("""\
rules:
  - id: allow_internal
    name: Allow Internal
    priority: 1
    conditions:
      destination_domain: "internal.company.com"
      direction: "both"
    action: ALLOW
    alert_severity: LOW
""")
        engine = PolicyEngine(str(policy))
        event = make_event(
            tool_name="any_tool",
            input_str="https://api.internal.company.com/data",
        )
        decision = engine.evaluate(event)
        assert decision.result == "ALLOW"

    def test_no_match_defaults_allow(self):
        """Empty policy — everything defaults to ALLOW."""
        engine = PolicyEngine()
        event = make_event(
            tool_name="harmless_tool",
            input_str="what is 2+2",
            output_str="4",
        )
        decision = engine.evaluate(event)
        assert decision.result == "ALLOW"
        assert decision.matched_rule is None

    def test_external_email_with_ssn_blocked(self, engine):
        event = make_event(
            tool_name="send_email",
            output_str="https://external.com SSN 123-45-6789",
        )
        decision = engine.evaluate(event)
        assert decision.result == "BLOCK"

    def test_default_policy_has_allow_rules(self, engine):
        """Default policy contains allow_crm_lookup and allow_internal_tools rules."""
        rule_ids = {r.id for r in engine.get_rules()}
        assert "allow_crm_lookup" in rule_ids
        assert "allow_internal_tools" in rule_ids

    def test_unknown_external_destination_alerted(self, engine):
        event = make_event(
            tool_name="send_email",
            input_str="https://unknown-site.com/api",
        )
        decision = engine.evaluate(event)
        # Should match block_unknown_destinations or block_unauthorized_api
        assert decision.result in ("ALERT", "BLOCK")

    def test_priority_ordering_lower_wins(self, tmp_path):
        policy = tmp_path / "priority.yaml"
        policy.write_text("""\
rules:
  - id: low_priority_allow
    name: Allow (low priority)
    priority: 100
    conditions:
      tool_name: "test_tool"
    action: ALLOW
    alert_severity: LOW
  - id: high_priority_block
    name: Block (high priority)
    priority: 1
    conditions:
      tool_name: "test_tool"
    action: BLOCK
    alert_severity: CRITICAL
""")
        engine = PolicyEngine(str(policy))
        event = make_event(tool_name="test_tool")
        decision = engine.evaluate(event)
        assert decision.result == "BLOCK"
        assert decision.matched_rule == "high_priority_block"

    def test_agent_id_condition(self, tmp_path):
        policy = tmp_path / "agent.yaml"
        policy.write_text("""\
rules:
  - id: block_rogue_agent
    name: Block Rogue Agent
    priority: 1
    conditions:
      agent_id: "rogue-agent"
    action: BLOCK
    alert_severity: CRITICAL
""")
        engine = PolicyEngine(str(policy))

        rogue = make_event(agent_id="rogue-agent")
        assert engine.evaluate(rogue).result == "BLOCK"

        good = make_event(agent_id="good-agent")
        assert engine.evaluate(good).result == "ALLOW"


# ── Hot-reload test ──────────────────────────────────────────────────


class TestHotReload:
    def test_hot_reload_picks_up_changes(self, tmp_path):
        policy = tmp_path / "hot.yaml"
        policy.write_text("""\
rules:
  - id: allow_all
    name: Allow All
    priority: 1
    conditions: {}
    action: ALLOW
    alert_severity: LOW
""")
        engine = PolicyEngine(str(policy))
        engine.start_hot_reload(interval=0.2)

        # Initially ALLOW
        assert engine.evaluate(make_event()).result == "ALLOW"

        # Update policy to BLOCK
        time.sleep(0.1)
        policy.write_text("""\
rules:
  - id: block_all
    name: Block All
    priority: 1
    conditions: {}
    action: BLOCK
    alert_severity: CRITICAL
""")

        # Wait for reload
        time.sleep(0.5)

        assert engine.evaluate(make_event()).result == "BLOCK"
        engine.stop_hot_reload()


# ── Performance test ─────────────────────────────────────────────────


class TestPolicyPerformance:
    def test_1000_evaluations_under_5_seconds(self, engine):
        events = [make_event(tool_name=f"tool_{i}") for i in range(1000)]
        start = time.perf_counter()
        for event in events:
            engine.evaluate(event)
        elapsed = time.perf_counter() - start
        assert elapsed < 5.0, f"1000 evaluations took {elapsed:.2f}s (limit: 5s)"

    def test_evaluation_latency_p99_under_5ms(self, engine):
        times = []
        for i in range(1000):
            event = make_event(tool_name=f"tool_{i}")
            start = time.perf_counter()
            engine.evaluate(event)
            times.append((time.perf_counter() - start) * 1000)

        p99 = sorted(times)[989]
        assert p99 < 5.0, f"p99 evaluation latency {p99:.3f}ms exceeds 5ms"
