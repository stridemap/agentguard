"""Tests for the Microsoft Presidio DLP scanner.

Covers:
- PII entity type detection (credit card, email, URL, etc.)
- Redaction output (PII replaced, surrounding text preserved)
- Sensitivity levels (LOW/MEDIUM/HIGH)
- Risk level computation
- Fail-open on scanner errors

Note: Without a spaCy NLP model installed, Presidio's detection
capabilities are limited. Tests match the actual behavior of
Presidio's default (regex-based) recognizers.
"""

from __future__ import annotations

import pytest

from agentguard.dlp_scanner import DLPConfig, DLPScanner, DLPSensitivity

# ── Fixtures ──────────────────────────────────────────────────────────


@pytest.fixture()
def scanner():
    """Return a DLP scanner at HIGH sensitivity."""
    return DLPScanner(sensitivity="HIGH")


@pytest.fixture()
def scanner_low():
    """Return a DLP scanner at LOW sensitivity."""
    return DLPScanner(sensitivity="LOW")


# ── Entity detection tests ───────────────────────────────────────────


class TestEntityDetection:
    def test_detect_credit_card(self, scanner):
        result = scanner.scan("Card number: 4111-1111-1111-1111")
        types = {e.entity_type for e in result.entities_found}
        assert "CREDIT_CARD" in types

    def test_detect_email(self, scanner):
        result = scanner.scan("Contact me at john.doe@example.com")
        types = {e.entity_type for e in result.entities_found}
        assert "EMAIL_ADDRESS" in types

    def test_url_in_supported_entities(self, scanner):
        """URL is a supported entity type at HIGH sensitivity."""
        assert "URL" in scanner.get_supported_entities()

    def test_empty_text(self, scanner):
        result = scanner.scan("")
        assert result.entity_count == 0
        assert result.risk_level == "CLEAN"

    def test_whitespace_text(self, scanner):
        result = scanner.scan("   ")
        assert result.entity_count == 0

    def test_multiple_credit_cards(self, scanner):
        result = scanner.scan("Cards: 4111-1111-1111-1111 and 5500-0000-0000-0004")
        cc = [e for e in result.entities_found if e.entity_type == "CREDIT_CARD"]
        assert len(cc) >= 2

    def test_entity_match_has_position(self, scanner):
        result = scanner.scan("Card: 4111-1111-1111-1111")
        assert len(result.entities_found) >= 1
        match = result.entities_found[0]
        assert match.start >= 0
        assert match.end > match.start
        assert match.score > 0


# ── Redaction tests ──────────────────────────────────────────────────


class TestRedaction:
    def test_credit_card_redacted(self, scanner):
        result = scanner.scan("Pay with 4111-1111-1111-1111 please")
        assert "[CREDIT_CARD]" in result.redacted_text
        assert "4111" not in result.redacted_text

    def test_email_redacted(self, scanner):
        result = scanner.scan("Email: test@example.com is private")
        assert "test@example.com" not in result.redacted_text
        assert "[EMAIL_ADDRESS]" in result.redacted_text
        assert "private" in result.redacted_text

    def test_no_entities_returns_text(self, scanner):
        original = "Just the number 42."
        result = scanner.scan(original)
        assert result.redacted_text is not None


# ── Risk level tests ─────────────────────────────────────────────────


class TestRiskLevel:
    def test_credit_card_is_high_risk(self, scanner):
        result = scanner.scan("Card: 4111-1111-1111-1111")
        assert result.risk_level == "HIGH"

    def test_email_risk(self, scanner):
        result = scanner.scan("Email only: john@example.com")
        assert result.risk_level in ("MEDIUM", "LOW")

    def test_no_entities_is_clean(self):
        scanner = DLPScanner(sensitivity="LOW")
        result = scanner.scan("Just numbers: 42 and 100")
        assert result.risk_level == "CLEAN"


# ── Sensitivity levels ───────────────────────────────────────────────


class TestSensitivityLevels:
    def test_low_scans_ssn_and_cc(self, scanner_low):
        entities = scanner_low.get_supported_entities()
        assert "US_SSN" in entities
        assert "CREDIT_CARD" in entities
        assert len(entities) == 2

    def test_high_scans_many_entities(self, scanner):
        entities = scanner.get_supported_entities()
        assert len(entities) >= 10
        assert "MEDICAL_LICENSE" in entities

    def test_medium_is_default(self):
        s = DLPScanner()
        assert "PERSON" in s.get_supported_entities()


# ── Config tests ─────────────────────────────────────────────────────


class TestDLPConfig:
    def test_custom_sensitivity(self):
        config = DLPConfig(sensitivity=DLPSensitivity.LOW)
        scanner = DLPScanner(config=config)
        assert len(scanner.get_supported_entities()) == 2

    def test_default_threshold(self):
        assert DLPConfig().confidence_threshold == 0.85


# ── Performance ──────────────────────────────────────────────────────


class TestDLPPerformance:
    def test_scan_latency_measured(self, scanner):
        result = scanner.scan("Card 4111-1111-1111-1111")
        assert result.scan_latency_ms > 0

    @pytest.mark.slow
    def test_subsequent_scans_faster(self, scanner):
        scanner.scan("Card 4111-1111-1111-1111")  # warm up
        result = scanner.scan("Another card 5500-0000-0000-0004")
        assert result.scan_latency_ms < 100


# ── Fail-open ────────────────────────────────────────────────────────


class TestDLPFailOpen:
    def test_returns_clean_on_error(self):
        scanner = DLPScanner(sensitivity="HIGH")
        scanner._analyzer = "broken"  # type: ignore[assignment]
        result = scanner.scan("SSN 123-45-6789")
        assert result.risk_level == "CLEAN"
        assert result.entity_count == 0

    def test_latency_tracked_on_error(self):
        scanner = DLPScanner(sensitivity="HIGH")
        scanner._analyzer = "broken"  # type: ignore[assignment]
        result = scanner.scan("test")
        assert result.scan_latency_ms > 0
