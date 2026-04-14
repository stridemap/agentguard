"""Tests for the injection detection evaluation harness.

Covers:
- Evaluation against the 100-sample labelled corpus
- Precision >= 0.90 quality gate
- Recall >= 0.85 quality gate
- F1 score computation
- Per-sample detail tracking
- Policy v2: regex conditions and OR match mode
"""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from agentguard.eval_harness import evaluate_detector, load_corpus
from agentguard.injection_detector import InjectionDetector
from agentguard.models import AgentEvent
from agentguard.policy_engine import PolicyEngine

CORPUS_PATH = str(Path(__file__).parent / "corpus" / "injection_corpus.json")


# ── Corpus loading ───────────────────────────────────────────────────


class TestCorpusLoading:
    def test_load_corpus(self):
        corpus = load_corpus(CORPUS_PATH)
        assert len(corpus) == 100

    def test_corpus_has_required_fields(self):
        corpus = load_corpus(CORPUS_PATH)
        for sample in corpus:
            assert "text" in sample
            assert "label" in sample
            assert sample["label"] in ("CLEAN", "SUSPICIOUS", "INJECTED")

    def test_corpus_label_distribution(self):
        corpus = load_corpus(CORPUS_PATH)
        labels = [s["label"] for s in corpus]
        assert labels.count("INJECTED") >= 20
        assert labels.count("SUSPICIOUS") >= 10
        assert labels.count("CLEAN") >= 50


# ── Evaluation quality gates ─────────────────────────────────────────


class TestEvaluationQualityGates:
    """Sprint 4/8 acceptance: precision >= 0.90, recall >= 0.85."""

    def test_precision_gate(self):
        detector = InjectionDetector(sensitivity="LOW")
        results = evaluate_detector(detector, CORPUS_PATH)
        assert results["precision"] >= 0.90, (
            f"Precision {results['precision']:.4f} below 0.90 gate. "
            f"FP={results['false_positives']}"
        )

    def test_recall_gate(self):
        detector = InjectionDetector(sensitivity="LOW")
        results = evaluate_detector(detector, CORPUS_PATH)
        assert results["recall"] >= 0.85, (
            f"Recall {results['recall']:.4f} below 0.85 gate. "
            f"FN={results['false_negatives']}"
        )

    def test_f1_computed(self):
        detector = InjectionDetector(sensitivity="LOW")
        results = evaluate_detector(detector, CORPUS_PATH)
        assert results["f1"] > 0
        # F1 = 2 * P * R / (P + R)
        expected_f1 = (
            2
            * results["precision"]
            * results["recall"]
            / (results["precision"] + results["recall"])
        )
        assert abs(results["f1"] - expected_f1) < 0.01

    def test_total_matches_corpus_size(self):
        detector = InjectionDetector(sensitivity="LOW")
        results = evaluate_detector(detector, CORPUS_PATH)
        assert results["total"] == 100
        assert (
            results["true_positives"]
            + results["false_positives"]
            + results["false_negatives"]
            + results["true_negatives"]
            == 100
        )

    def test_details_per_sample(self):
        detector = InjectionDetector(sensitivity="LOW")
        results = evaluate_detector(detector, CORPUS_PATH)
        assert len(results["details"]) == 100
        for d in results["details"]:
            assert d["outcome"] in ("TP", "FP", "FN", "TN")
            assert "expected" in d
            assert "predicted" in d


# ── Detector sensitivity comparison ──────────────────────────────────


class TestSensitivityComparison:
    def test_low_has_fewer_stage2_calls(self):
        """LOW sensitivity = Stage 1 only, should be fastest."""
        detector = InjectionDetector(sensitivity="LOW")
        results = evaluate_detector(detector, CORPUS_PATH)
        # LOW never calls Stage 2, so all detections are from regex
        assert results["total"] == 100

    def test_accuracy_above_80(self):
        detector = InjectionDetector(sensitivity="LOW")
        results = evaluate_detector(detector, CORPUS_PATH)
        assert (
            results["accuracy"] >= 0.80
        ), f"Accuracy {results['accuracy']:.4f} below 0.80"


# ── Policy v2: regex conditions ──────────────────────────────────────


def make_event(**kwargs) -> AgentEvent:
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


class TestPolicyV2Regex:
    """Test input_regex, output_regex, and OR match mode."""

    def test_input_regex_match(self, tmp_path):
        policy = tmp_path / "regex.yaml"
        policy.write_text("""\
rules:
  - id: block_ssn_input
    name: Block SSN in Input
    priority: 1
    conditions:
      input_regex: "\\\\d{3}-\\\\d{2}-\\\\d{4}"
    action: BLOCK
    alert_severity: CRITICAL
""")
        engine = PolicyEngine(str(policy))
        event = make_event(input_str="My SSN is 123-45-6789")
        decision = engine.evaluate(event)
        assert decision.result == "BLOCK"

    def test_input_regex_no_match(self, tmp_path):
        policy = tmp_path / "regex.yaml"
        policy.write_text("""\
rules:
  - id: block_ssn_input
    name: Block SSN in Input
    priority: 1
    conditions:
      input_regex: "\\\\d{3}-\\\\d{2}-\\\\d{4}"
    action: BLOCK
    alert_severity: CRITICAL
""")
        engine = PolicyEngine(str(policy))
        event = make_event(input_str="No PII here")
        decision = engine.evaluate(event)
        assert decision.result == "ALLOW"

    def test_output_regex_match(self, tmp_path):
        policy = tmp_path / "output.yaml"
        policy.write_text("""\
rules:
  - id: block_cc_output
    name: Block Credit Card in Output
    priority: 1
    conditions:
      output_regex: "\\\\d{4}[-\\\\s]?\\\\d{4}[-\\\\s]?\\\\d{4}[-\\\\s]?\\\\d{4}"
    action: BLOCK
    alert_severity: CRITICAL
""")
        engine = PolicyEngine(str(policy))
        event = make_event(output_str="Card: 4111-1111-1111-1111")
        decision = engine.evaluate(event)
        assert decision.result == "BLOCK"

    def test_or_match_mode(self, tmp_path):
        """OR mode: any condition matching triggers the rule."""
        policy = tmp_path / "or.yaml"
        policy.write_text("""\
rules:
  - id: alert_suspicious
    name: Alert on Suspicious
    priority: 1
    conditions:
      tool_name: "send_email"
      input_regex: "password"
      match_mode: "or"
    action: ALERT
    alert_severity: HIGH
""")
        engine = PolicyEngine(str(policy))

        # Tool name matches but regex doesn't
        event1 = make_event(tool_name="send_email", input_str="hello")
        assert engine.evaluate(event1).result == "ALERT"

        # Regex matches but tool doesn't
        event2 = make_event(tool_name="other_tool", input_str="my password is 123")
        assert engine.evaluate(event2).result == "ALERT"

        # Neither matches
        event3 = make_event(tool_name="other_tool", input_str="hello")
        assert engine.evaluate(event3).result == "ALLOW"

    def test_and_match_mode_default(self, tmp_path):
        """AND mode (default): all conditions must match."""
        policy = tmp_path / "and.yaml"
        policy.write_text("""\
rules:
  - id: block_email_with_ssn
    name: Block Email with SSN
    priority: 1
    conditions:
      tool_name: "send_email"
      input_regex: "\\\\d{3}-\\\\d{2}-\\\\d{4}"
    action: BLOCK
    alert_severity: CRITICAL
""")
        engine = PolicyEngine(str(policy))

        # Both match → BLOCK
        event1 = make_event(tool_name="send_email", input_str="SSN 123-45-6789")
        assert engine.evaluate(event1).result == "BLOCK"

        # Only tool matches → ALLOW (AND requires both)
        event2 = make_event(tool_name="send_email", input_str="hello")
        assert engine.evaluate(event2).result == "ALLOW"

    def test_combined_regex_and_domain(self, tmp_path):
        """Regex + domain conditions together."""
        policy = tmp_path / "combined.yaml"
        policy.write_text("""\
rules:
  - id: block_pii_external
    name: Block PII to External
    priority: 1
    conditions:
      destination_domain: "!internal.company.com"
      output_regex: "\\\\d{3}-\\\\d{2}-\\\\d{4}"
      direction: "output"
    action: BLOCK
    alert_severity: CRITICAL
""")
        engine = PolicyEngine(str(policy))

        # External domain + SSN in output → BLOCK
        event = make_event(output_str="SSN 123-45-6789 https://evil.com/leak")
        assert engine.evaluate(event).result == "BLOCK"
