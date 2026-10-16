"""YAML-based policy rule engine for tool-call governance.

Evaluates every tool-call event against a list of YAML-defined rules
and returns a PolicyDecision (ALLOW / BLOCK / ALERT / BYPASS).

Rules are evaluated in priority order (lower number = higher priority).
First matching rule wins. If no rule matches, the default is ALLOW
(fail-open design).

Supports hot-reload: watches the policy file for changes and reloads
rules without restarting the agent.

Usage:
    from agentguard.policy_engine import PolicyEngine

    engine = PolicyEngine("policies/default.yaml")
    decision = engine.evaluate(event)
    # decision.result == "ALLOW" | "BLOCK" | "ALERT" | "BYPASS"
"""

from __future__ import annotations

import os
import re
import threading
import time
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, field_validator

from agentguard.logging import logger
from agentguard.models import AgentEvent

# ── Decision model ───────────────────────────────────────────────────


class PolicyDecision(BaseModel):
    """Result of evaluating an event against the policy rules."""

    result: str = Field(description="ALLOW | BLOCK | ALERT | BYPASS")
    matched_rule: str | None = Field(
        default=None, description="ID of the rule that matched, or None"
    )
    reason: str = Field(
        default="No rule matched — default ALLOW",
        description="Human-readable explanation",
    )
    alert_severity: str | None = Field(
        default=None, description="LOW | MEDIUM | HIGH | CRITICAL (if ALERT)"
    )


# ── Rule schema ──────────────────────────────────────────────────────


class PolicyConditions(BaseModel):
    """Conditions for a rule to match.

    Default match_mode is 'and' — all non-null conditions must match.
    Set match_mode to 'or' for any-condition matching.
    """

    tool_name: str | list[str] | None = Field(
        default=None, description="Tool name string, regex, or list. None = any tool."
    )
    destination_domain: str | list[str] | None = Field(
        default=None,
        description="Domain string or list. Prefix with ! for NOT match. None = any domain.",
    )
    data_pattern: str | None = Field(
        default=None,
        description="PII entity type (e.g. US_SSN). None = skip DLP check.",
    )
    direction: str = Field(default="both", description="'input' | 'output' | 'both'")
    agent_id: str | None = Field(
        default=None, description="Agent ID to match. None = any agent."
    )
    input_regex: str | None = Field(
        default=None,
        description="Regex pattern to match against input_str. None = skip.",
    )
    output_regex: str | None = Field(
        default=None,
        description="Regex pattern to match against output_str. None = skip.",
    )
    match_mode: str = Field(
        default="and",
        description="'and' = all conditions must match, 'or' = any condition matches.",
    )


class PolicyRule(BaseModel):
    """A single policy rule with conditions and action."""

    id: str = Field(description="Unique rule identifier")
    name: str = Field(description="Human-readable rule name")
    description: str = Field(default="", description="What this rule does")
    priority: int = Field(default=100, description="Lower number = higher priority")
    conditions: PolicyConditions = Field(default_factory=PolicyConditions)
    action: str = Field(description="ALLOW | BLOCK | ALERT | BYPASS")
    alert_severity: str = Field(
        default="LOW", description="LOW | MEDIUM | HIGH | CRITICAL"
    )

    @field_validator("action")
    @classmethod
    def validate_action(cls, v: str) -> str:
        valid = {"ALLOW", "BLOCK", "ALERT", "BYPASS"}
        upper = v.upper()
        if upper not in valid:
            msg = f"Invalid action '{v}'. Must be one of: {valid}"
            raise ValueError(msg)
        return upper

    @field_validator("alert_severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        valid = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        upper = v.upper()
        if upper not in valid:
            msg = f"Invalid severity '{v}'. Must be one of: {valid}"
            raise ValueError(msg)
        return upper


class PolicyConfig(BaseModel):
    """Top-level policy file schema."""

    rules: list[PolicyRule] = Field(default_factory=list)


# ── Validation error ─────────────────────────────────────────────────


class PolicyValidationError(Exception):
    """Raised when a policy YAML file fails validation."""


# ── Engine ───────────────────────────────────────────────────────────


class PolicyEngine:
    """YAML policy rule engine with in-memory evaluation and hot-reload.

    Attributes:
        policy_path: Path to the YAML policy file.
        rules: List of validated PolicyRule instances, sorted by priority.
    """

    def __init__(self, policy_path: str | None = None) -> None:
        """Initialize the policy engine.

        Args:
            policy_path: Path to a YAML policy file. If None, engine
                starts with no rules (default ALLOW on everything).
        """
        self.policy_path = policy_path
        self.rules: list[PolicyRule] = []
        self._lock = threading.Lock()
        self._file_mtime: float = 0.0
        self._reload_thread: threading.Thread | None = None
        self._reload_running = False

        if policy_path is not None:
            self.load_policies(policy_path)

    def load_policies(self, path: str) -> None:
        """Load and validate policy rules from a YAML file.

        Args:
            path: Path to the YAML policy file.

        Raises:
            PolicyValidationError: If the YAML is invalid or fails schema validation.
            FileNotFoundError: If the file doesn't exist.
        """
        policy_path = Path(path)
        if not policy_path.exists():
            msg = f"Policy file not found: {path}"
            raise FileNotFoundError(msg)

        try:
            raw = policy_path.read_text(encoding="utf-8")
            data = yaml.safe_load(raw)

            if data is None:
                data = {"rules": []}

            config = PolicyConfig.model_validate(data)
            sorted_rules = sorted(config.rules, key=lambda r: r.priority)

            with self._lock:
                self.rules = sorted_rules
                self.policy_path = path
                self._file_mtime = os.path.getmtime(path)

            logger.bind(module="agentguard.policy_engine").info(
                "Loaded {count} policy rules from {path}",
                count=len(sorted_rules),
                path=path,
            )

        except yaml.YAMLError as e:
            msg = f"Invalid YAML in {path}: {e}"
            raise PolicyValidationError(msg) from e
        except Exception as e:
            if isinstance(e, (FileNotFoundError, PolicyValidationError)):
                raise
            msg = f"Policy validation error in {path}: {e}"
            raise PolicyValidationError(msg) from e

    def evaluate(self, event: AgentEvent) -> PolicyDecision:
        """Evaluate an event against all loaded rules.

        Rules are checked in priority order (lowest number first).
        First matching rule wins. If no rule matches, returns ALLOW.

        Evaluation is in-memory only — no database or network calls.

        Args:
            event: The AgentEvent to evaluate.

        Returns:
            PolicyDecision with result, matched rule, and reason.
        """
        with self._lock:
            rules = list(self.rules)

        for rule in rules:
            if self._matches(rule, event):
                return PolicyDecision(
                    result=rule.action,
                    matched_rule=rule.id,
                    reason=f"Matched rule '{rule.name}': {rule.description}",
                    alert_severity=(
                        rule.alert_severity if rule.action == "ALERT" else None
                    ),
                )

        return PolicyDecision(
            result="ALLOW",
            matched_rule=None,
            reason="No rule matched — default ALLOW",
        )

    def _matches(self, rule: PolicyRule, event: AgentEvent) -> bool:
        """Check if conditions match the event.

        match_mode='and' (default): all non-null conditions must match.
        match_mode='or': any non-null condition matching is sufficient.
        Null conditions are wildcards (always true in AND, ignored in OR).
        """
        cond = rule.conditions
        checks: list[bool] = []

        # agent_id
        if cond.agent_id is not None:
            checks.append(cond.agent_id == event.agent_id)

        # tool_name
        if cond.tool_name is not None:
            checks.append(self._matches_tool_name(cond.tool_name, event.tool_name))

        # destination_domain
        if cond.destination_domain is not None:
            text = self._get_text_for_direction(event, cond.direction)
            checks.append(self._matches_domain(cond.destination_domain, text))

        # data_pattern
        if cond.data_pattern is not None:
            checks.append(self._matches_data_pattern(cond.data_pattern, event))

        # input_regex (v2)
        if cond.input_regex is not None:
            checks.append(
                bool(re.search(cond.input_regex, event.input_str, re.IGNORECASE))
            )

        # output_regex (v2)
        if cond.output_regex is not None:
            checks.append(
                bool(re.search(cond.output_regex, event.output_str, re.IGNORECASE))
            )

        # No conditions set = wildcard match
        if not checks:
            return True

        if cond.match_mode == "or":
            return any(checks)
        return all(checks)

    @staticmethod
    def _matches_tool_name(pattern: str | list[str], tool_name: str) -> bool:
        """Check if tool_name matches a string, regex, or list of patterns."""
        if isinstance(pattern, list):
            return any(PolicyEngine._matches_tool_name(p, tool_name) for p in pattern)
        # Try exact match first, then regex
        if pattern == tool_name:
            return True
        try:
            return bool(re.fullmatch(pattern, tool_name))
        except re.error:
            return False

    @staticmethod
    def _matches_domain(pattern: str | list[str], text: str) -> bool:
        """Check if text contains URLs matching the domain condition."""
        if isinstance(pattern, list):
            return any(PolicyEngine._matches_domain(p, text) for p in pattern)

        negate = pattern.startswith("!")
        domain = pattern.lstrip("!")

        urls = re.findall(r"https?://([^\s/\"'<>]+)", text, re.IGNORECASE)
        if not urls:
            # No URLs found — negated domain matches (no external URL)
            return negate

        for url_domain in urls:
            is_match = (
                url_domain.lower() == domain.lower()
                or url_domain.lower().endswith("." + domain.lower())
            )
            if negate and is_match:
                return False  # Found URL matching negated domain
            if not negate and is_match:
                return True

        return negate  # If negated, no matching URL found = True

    @staticmethod
    def _matches_data_pattern(pattern: str, event: AgentEvent) -> bool:
        """Whether the event carries the named PII entity type.

        Checked in order of reliability. The scanner's own findings come first: they
        survive redaction, which the raw-text fallback does not — a redacted payload has
        had the value replaced, so a rule that depended on matching the digits would
        silently stop firing exactly when redaction was switched on.
        """
        pattern_lower = pattern.lower()

        # What the DLP scanner reported, by entity type.
        for entity in event.dlp_entities:
            if pattern_lower == str(entity).lower():
                return True

        # Generic risk flags, for callers that record no entity types.
        for flag in event.risk_flags:
            if pattern_lower in str(flag).lower():
                return True
        # Also do a simple text search for common PII patterns
        combined = event.input_str + " " + event.output_str
        pii_patterns = {
            "us_ssn": r"\b\d{3}-\d{2}-\d{4}\b",
            "credit_card": r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",
            "email_address": r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
            "phone_number": r"\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}",
        }
        regex = pii_patterns.get(pattern_lower)
        return bool(regex and re.search(regex, combined))

    @staticmethod
    def _get_text_for_direction(event: AgentEvent, direction: str) -> str:
        """Get the relevant text based on direction condition."""
        if direction == "input":
            return event.input_str
        if direction == "output":
            return event.output_str
        return event.input_str + " " + event.output_str

    # ── Hot-reload ───────────────────────────────────────────────────

    def start_hot_reload(self, interval: float = 1.0) -> None:
        """Start a background thread that watches for policy file changes.

        Args:
            interval: Seconds between file modification checks.
        """
        if self._reload_running or self.policy_path is None:
            return

        self._reload_running = True
        self._reload_thread = threading.Thread(
            target=self._hot_reload_loop,
            args=(interval,),
            name="agentguard-policy-reload",
            daemon=True,
        )
        self._reload_thread.start()
        logger.bind(module="agentguard.policy_engine").info(
            "Policy hot-reload started (interval={interval}s)",
            interval=interval,
        )

    def stop_hot_reload(self) -> None:
        """Stop the hot-reload background thread."""
        self._reload_running = False
        if self._reload_thread is not None:
            self._reload_thread.join(timeout=3.0)
            self._reload_thread = None

    def _hot_reload_loop(self, interval: float) -> None:
        """Background loop that reloads policy when the file changes."""
        while self._reload_running and self.policy_path is not None:
            try:
                current_mtime = os.path.getmtime(self.policy_path)
                if current_mtime > self._file_mtime:
                    self.load_policies(self.policy_path)
                    logger.bind(module="agentguard.policy_engine").info(
                        "Policy hot-reloaded from {path}",
                        path=self.policy_path,
                    )
            except Exception as e:
                logger.warning(
                    "Policy hot-reload error (keeping current rules): {error}",
                    error=str(e),
                )
            time.sleep(interval)

    # ── Public API ───────────────────────────────────────────────────

    def get_rules(self) -> list[PolicyRule]:
        """Return a copy of the current rules."""
        with self._lock:
            return list(self.rules)

    def get_rule_count(self) -> int:
        """Return the number of loaded rules."""
        with self._lock:
            return len(self.rules)
