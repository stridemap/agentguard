"""Runtime guardrails for MiniGate — a thin, fail-open facade over AgentGuard.

Wraps `DLPScanner` and `InjectionDetector` so the gateway can call them without
caring whether they are enabled, installed, or healthy. Presidio is an optional
heavy dependency and is imported lazily by AgentGuard on first scan; if it is
missing or throws, scanning degrades to a no-op rather than taking the gateway
down with it.
"""

from __future__ import annotations

from dataclasses import dataclass

from agentguard.dlp_scanner import DLPScanner
from agentguard.injection_detector import InjectionDetector
from minigate.config import DLPSettings, InjectionSettings
from minigate.logging import logger


@dataclass
class ScanOutcome:
    """Combined result of scanning one payload."""

    text: str
    """The payload to forward — redacted if PII was found and redaction is on."""

    entities: list[str]
    """PII entity types detected, e.g. ["US_SSN", "EMAIL_ADDRESS"]."""

    entity_values: list[str]
    """The matched text itself, for lineage hashing only.

    Never persisted and never logged: the lineage tracker hashes these immediately.
    They exist because Presidio finds a record embedded in prose that structural
    extraction would miss.
    """

    injection_status: str
    """CLEAN | SUSPICIOUS | INJECTED."""

    @property
    def is_injected(self) -> bool:
        return self.injection_status == "INJECTED"


class Guardrails:
    """DLP and prompt-injection scanning, individually toggleable and fail-open."""

    def __init__(
        self,
        dlp_settings: DLPSettings | None = None,
        injection_settings: InjectionSettings | None = None,
    ) -> None:
        self.dlp_settings = dlp_settings or DLPSettings()
        self.injection_settings = injection_settings or InjectionSettings()

        self._dlp = DLPScanner(sensitivity=self.dlp_settings.sensitivity) if self.dlp_settings.enabled else None
        self._injection = (
            InjectionDetector(sensitivity=self.injection_settings.sensitivity)
            if self.injection_settings.enabled
            else None
        )
        self._dlp_failed = False

    def scan(self, text: str, *, redact: bool) -> ScanOutcome:
        """Scan a payload for PII and prompt injection.

        Any scanner failure is logged once and degrades to a pass-through — a broken
        guardrail must not break the agent. Policy BLOCK decisions are unaffected.

        Args:
            text: The payload to scan.
            redact: Whether to substitute redacted text for the original.

        Returns:
            A ScanOutcome carrying the (possibly redacted) text and what was found.
        """
        if not text:
            return ScanOutcome(text=text, entities=[], entity_values=[], injection_status="CLEAN")

        out_text = text
        entities: list[str] = []
        entity_values: list[str] = []
        injection_status = "CLEAN"

        if self._dlp is not None and not self._dlp_failed:
            try:
                result = self._dlp.scan(text)
                entities = sorted({e.entity_type for e in result.entities_found})
                entity_values = [e.text for e in result.entities_found if e.text]
                if entities and redact and result.redacted_text:
                    out_text = result.redacted_text
            except Exception as e:
                # Presidio missing or misconfigured — disable rather than retry per call.
                self._dlp_failed = True
                logger.bind(module="minigate.guardrails").warning(
                    "DLP scanning disabled after error (fail-open): {error}", error=str(e)
                )

        if self._injection is not None:
            try:
                injection_status = self._injection.scan(text).status
            except Exception as e:
                logger.bind(module="minigate.guardrails").warning(
                    "Injection scan failed (fail-open): {error}", error=str(e)
                )

        return ScanOutcome(
            text=out_text,
            entities=entities,
            entity_values=entity_values,
            injection_status=injection_status,
        )

    def scan_tool_description(self, description: str) -> str:
        """Scan a tool description advertised on tools/list.

        A malicious server can hide instructions in a tool description to exploit the
        model's deference to authoritative-sounding text — the tool never has to be
        called for the attack to land. Returns the injection status.
        """
        if not self.injection_settings.scan_tool_descriptions or self._injection is None:
            return "CLEAN"
        try:
            return self._injection.scan(description).status
        except Exception as e:
            logger.bind(module="minigate.guardrails").warning(
                "Tool description scan failed (fail-open): {error}", error=str(e)
            )
            return "CLEAN"
