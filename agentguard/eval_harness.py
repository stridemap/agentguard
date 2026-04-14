"""Injection detection evaluation harness.

Runs the InjectionDetector against a labelled corpus and computes
precision, recall, and F1 score. Used as a per-release quality gate.

Usage:
    from agentguard.eval_harness import evaluate_detector

    results = evaluate_detector(detector, corpus_path)
    assert results["precision"] >= 0.90
    assert results["recall"] >= 0.85
"""

from __future__ import annotations

import json
from pathlib import Path

from agentguard.injection_detector import InjectionDetector


def load_corpus(path: str) -> list[dict]:
    """Load a labelled injection corpus from a JSON file.

    Expected format: [{"text": "...", "label": "CLEAN|SUSPICIOUS|INJECTED", "owasp": "..."}]
    """
    return json.loads(Path(path).read_text(encoding="utf-8"))


def evaluate_detector(
    detector: InjectionDetector,
    corpus_path: str,
    positive_labels: set[str] | None = None,
) -> dict:
    """Evaluate detector precision, recall, and F1 against a labelled corpus.

    Treats INJECTED and SUSPICIOUS as "positive" (attack detected) by default.
    CLEAN is negative.

    Args:
        detector: The InjectionDetector to evaluate.
        corpus_path: Path to the labelled JSON corpus.
        positive_labels: Labels to treat as positive. Default: {"INJECTED", "SUSPICIOUS"}.

    Returns:
        Dict with precision, recall, f1, total, true_positives, false_positives,
        false_negatives, true_negatives, accuracy, and per-sample details.
    """
    if positive_labels is None:
        positive_labels = {"INJECTED", "SUSPICIOUS"}

    corpus = load_corpus(corpus_path)

    tp = 0  # true positive: label=positive, predicted=positive
    fp = 0  # false positive: label=CLEAN, predicted=positive
    fn = 0  # false negative: label=positive, predicted=CLEAN
    tn = 0  # true negative: label=CLEAN, predicted=CLEAN
    details: list[dict] = []

    for sample in corpus:
        text = sample["text"]
        expected_label = sample["label"]
        expected_positive = expected_label in positive_labels

        result = detector.scan(text)
        # Consider anything non-CLEAN as a detection
        predicted_positive = result.status != "CLEAN"

        if expected_positive and predicted_positive:
            tp += 1
            outcome = "TP"
        elif not expected_positive and predicted_positive:
            fp += 1
            outcome = "FP"
        elif expected_positive and not predicted_positive:
            fn += 1
            outcome = "FN"
        else:
            tn += 1
            outcome = "TN"

        details.append(
            {
                "text": text[:80],
                "expected": expected_label,
                "predicted": result.status,
                "outcome": outcome,
                "confidence": result.confidence,
                "patterns": result.matched_patterns,
            }
        )

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )
    accuracy = (tp + tn) / len(corpus) if corpus else 0.0

    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round(accuracy, 4),
        "total": len(corpus),
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "true_negatives": tn,
        "details": details,
    }
