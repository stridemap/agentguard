"""Microsoft Presidio DLP scanner for PII detection and redaction.

Scans tool-call inputs and outputs for PII entities using Microsoft
Presidio. Runs 100% locally — zero data sent externally.

Supports 15+ entity types: PERSON, EMAIL_ADDRESS, PHONE_NUMBER,
US_SSN, CREDIT_CARD, MEDICAL_LICENSE, DATE_TIME, IP_ADDRESS, URL, etc.

Usage:
    from agentguard.dlp_scanner import DLPScanner

    scanner = DLPScanner(sensitivity="HIGH")
    result = scanner.scan("My SSN is 123-45-6789")
    # result.entities_found = [EntityMatch(entity_type="US_SSN", ...)]
"""

from __future__ import annotations

import time
from enum import StrEnum

from pydantic import BaseModel, Field

from agentguard.logging import logger

# ── Models ───────────────────────────────────────────────────────────


class DLPSensitivity(StrEnum):
    """DLP scanning sensitivity levels."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class EntityMatch(BaseModel):
    """A single PII entity detected in text."""

    entity_type: str = Field(description="Presidio entity type (e.g. US_SSN)")
    text: str = Field(description="The matched PII text")
    start: int = Field(description="Start character offset")
    end: int = Field(description="End character offset")
    score: float = Field(description="Confidence score (0.0 to 1.0)")


class DLPResult(BaseModel):
    """Result of a DLP scan on a text input."""

    entities_found: list[EntityMatch] = Field(default_factory=list)
    redacted_text: str = Field(
        default="", description="Text with PII replaced by [ENTITY_TYPE]"
    )
    risk_level: str = Field(default="CLEAN", description="CLEAN | LOW | MEDIUM | HIGH")
    scan_latency_ms: float = Field(default=0.0, description="Scan time in milliseconds")
    entity_count: int = Field(default=0, description="Number of entities detected")


class DLPConfig(BaseModel):
    """Configuration for the DLP scanner."""

    sensitivity: DLPSensitivity = Field(
        default=DLPSensitivity.MEDIUM,
        description="Scanning sensitivity level",
    )
    confidence_threshold: float = Field(
        default=0.85,
        description="Minimum confidence score to report an entity",
    )
    entities_low: list[str] = Field(
        default_factory=lambda: ["CREDIT_CARD", "US_SSN"],
        description="Entity types scanned at LOW sensitivity",
    )
    entities_medium: list[str] = Field(
        default_factory=lambda: [
            "CREDIT_CARD",
            "US_SSN",
            "PERSON",
            "EMAIL_ADDRESS",
            "PHONE_NUMBER",
            "US_BANK_NUMBER",
            "IBAN_CODE",
        ],
        description="Entity types scanned at MEDIUM sensitivity",
    )
    entities_high: list[str] = Field(
        default_factory=lambda: [
            "CREDIT_CARD",
            "US_SSN",
            "PERSON",
            "EMAIL_ADDRESS",
            "PHONE_NUMBER",
            "US_BANK_NUMBER",
            "IBAN_CODE",
            "MEDICAL_LICENSE",
            "DATE_TIME",
            "IP_ADDRESS",
            "URL",
            "LOCATION",
            "NRP",
            "US_DRIVER_LICENSE",
            "US_PASSPORT",
        ],
        description="Entity types scanned at HIGH sensitivity",
    )


# ── Scanner ──────────────────────────────────────────────────────────


class DLPScanner:
    """Microsoft Presidio-based PII scanner — 100% local, zero data egress.

    Attributes:
        config: DLP scanner configuration.
    """

    def __init__(
        self,
        sensitivity: str = "MEDIUM",
        config: DLPConfig | None = None,
    ) -> None:
        """Initialize the DLP scanner.

        Lazily creates the Presidio AnalyzerEngine on first scan to
        avoid import overhead if DLP is not used.

        Args:
            sensitivity: LOW | MEDIUM | HIGH scanning level.
            config: Optional full configuration.
        """
        if config is not None:
            self.config = config
        else:
            self.config = DLPConfig(sensitivity=DLPSensitivity(sensitivity))

        self._analyzer = None
        self._anonymizer = None

    def _get_analyzer(self):
        """Lazily initialize the Presidio AnalyzerEngine."""
        if self._analyzer is None:
            from presidio_analyzer import AnalyzerEngine

            self._analyzer = AnalyzerEngine()
            logger.bind(module="agentguard.dlp_scanner").info(
                "Presidio AnalyzerEngine initialized"
            )
        return self._analyzer

    def _get_anonymizer(self):
        """Lazily initialize the Presidio AnonymizerEngine."""
        if self._anonymizer is None:
            from presidio_anonymizer import AnonymizerEngine

            self._anonymizer = AnonymizerEngine()
        return self._anonymizer

    def _get_entities_for_sensitivity(self) -> list[str]:
        """Return the entity types for the current sensitivity level."""
        level = self.config.sensitivity
        if level == DLPSensitivity.LOW:
            return self.config.entities_low
        if level == DLPSensitivity.HIGH:
            return self.config.entities_high
        return self.config.entities_medium

    def scan(self, text: str, direction: str = "both") -> DLPResult:
        """Scan text for PII entities.

        Args:
            text: The text to scan.
            direction: 'input' | 'output' | 'both' (for logging context).

        Returns:
            DLPResult with entities found, redacted text, and risk level.
        """
        if not text or not text.strip():
            return DLPResult(redacted_text=text)

        start_time = time.perf_counter()

        try:
            analyzer = self._get_analyzer()
            entities = self._get_entities_for_sensitivity()

            results = analyzer.analyze(
                text=text,
                entities=entities,
                language="en",
                score_threshold=self.config.confidence_threshold,
            )

            # Convert to EntityMatch models
            matches = [
                EntityMatch(
                    entity_type=r.entity_type,
                    text=text[r.start : r.end],
                    start=r.start,
                    end=r.end,
                    score=r.score,
                )
                for r in results
            ]

            # Compute redacted text
            redacted = self._redact(text, matches)

            # Determine risk level
            risk_level = self._compute_risk_level(matches)

            latency_ms = (time.perf_counter() - start_time) * 1000

            if matches:
                logger.bind(module="agentguard.dlp_scanner").info(
                    "DLP scan found {count} entities ({types}) direction={direction} latency={latency:.1f}ms",
                    count=len(matches),
                    types=", ".join(sorted({m.entity_type for m in matches})),
                    direction=direction,
                    latency=latency_ms,
                )

            return DLPResult(
                entities_found=matches,
                redacted_text=redacted,
                risk_level=risk_level,
                scan_latency_ms=latency_ms,
                entity_count=len(matches),
            )

        except Exception as e:
            latency_ms = (time.perf_counter() - start_time) * 1000
            logger.opt(exception=True).warning(
                "DLP scan error (fail-open): {error}", error=str(e)
            )
            return DLPResult(
                redacted_text=text,
                risk_level="CLEAN",
                scan_latency_ms=latency_ms,
            )

    def _redact(self, text: str, matches: list[EntityMatch]) -> str:
        """Replace PII entities with [ENTITY_TYPE] placeholders.

        Args:
            text: Original text.
            matches: List of detected entities.

        Returns:
            Text with PII replaced.
        """
        if not matches:
            return text

        # Sort by start position descending to replace from end to start
        sorted_matches = sorted(matches, key=lambda m: m.start, reverse=True)
        result = text
        for match in sorted_matches:
            placeholder = f"[{match.entity_type}]"
            result = result[: match.start] + placeholder + result[match.end :]
        return result

    @staticmethod
    def _compute_risk_level(matches: list[EntityMatch]) -> str:
        """Determine the risk level based on detected entities."""
        if not matches:
            return "CLEAN"

        high_risk_types = {"US_SSN", "CREDIT_CARD", "MEDICAL_LICENSE", "US_PASSPORT"}
        medium_risk_types = {
            "PERSON",
            "PHONE_NUMBER",
            "EMAIL_ADDRESS",
            "US_BANK_NUMBER",
        }

        entity_types = {m.entity_type for m in matches}

        if entity_types & high_risk_types:
            return "HIGH"
        if entity_types & medium_risk_types:
            return "MEDIUM"
        return "LOW"

    def get_supported_entities(self) -> list[str]:
        """Return the list of entity types for the current sensitivity level."""
        return self._get_entities_for_sensitivity()
