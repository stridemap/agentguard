"""Approved-tool registry with definition pinning.

Name-based policy cannot see a rug-pull: a tool passes review, then the server
changes its description or input schema afterwards. Because a description is
instructions the model reads and a schema decides what data the model hands over,
that change is a privilege escalation that no `tool_name` rule will catch.

The registry pins the full definition at approval time. On every `tools/list` each
advertised tool is hashed and compared to what was approved:

    APPROVED — hash matches; the tool is exactly what was reviewed
    CHANGED  — the server is advertising something else under an approved name
    UNKNOWN  — never reviewed

The whole tool object is hashed, not a chosen subset. Any field a server controls
can carry instructions, so a benign-looking addition still warrants re-approval —
noise here is a re-run of `minigate registry sync`, whereas a gap is an unreviewed
instruction reaching the model.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from minigate.logging import logger

REGISTRY_VERSION = 1


class RegistryVerdict(StrEnum):
    """What the registry says about a tool the server is advertising."""

    APPROVED = "APPROVED"
    CHANGED = "CHANGED"
    UNKNOWN = "UNKNOWN"

    UNVERIFIED = "UNVERIFIED"
    """A call arrived for a tool this session never saw advertised.

    A name matching an approved entry proves nothing — that is the exact case
    pinning exists to catch — so an unseen definition is never treated as approved.
    """


class RegistryMode(StrEnum):
    """How strictly a verdict is enforced."""

    OFF = "off"
    OBSERVE = "observe"
    """Audit UNKNOWN and CHANGED tools but let them through — use to bootstrap."""

    ENFORCE = "enforce"
    """Withhold anything not APPROVED from tools/list, and block calls to it."""


class ToolEntry(BaseModel):
    """One approved tool definition."""

    server: str
    name: str
    hash: str = Field(description="SHA-256 of the canonical tool definition")
    approved_at: str
    approved_by: str = Field(default="unknown")
    definition: dict[str, Any] = Field(
        default_factory=dict, description="Snapshot of what was approved, for diffing"
    )

    @property
    def key(self) -> tuple[str, str]:
        return (self.server, self.name)


class RegistryFile(BaseModel):
    """On-disk registry schema."""

    version: int = Field(default=REGISTRY_VERSION)
    tools: list[ToolEntry] = Field(default_factory=list)


def canonical_hash(tool: dict[str, Any]) -> str:
    """SHA-256 of a tool definition, stable across key ordering.

    Key order in JSON is not semantically meaningful, so a server re-serialising its
    manifest must not read as a change.
    """
    canonical = json.dumps(tool, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


class ToolRegistry:
    """Approved tool definitions, loaded from and saved to a YAML file.

    An empty registry in ENFORCE mode denies everything. That is the correct
    failure direction for an allowlist, but it is a sharp edge on first run — the
    gateway logs a warning, and `minigate registry sync` is how you populate it.
    """

    def __init__(self, path: str | None = None, mode: RegistryMode | str = RegistryMode.OBSERVE) -> None:
        self.path = path
        self.mode = RegistryMode(mode)
        self._entries: dict[tuple[str, str], ToolEntry] = {}
        if path is not None:
            self.load()

    # ── persistence ──────────────────────────────────────────────────

    def load(self) -> None:
        """Load the registry file. A missing file is an empty registry, not an error."""
        if self.path is None:
            return
        registry_path = Path(self.path)
        if not registry_path.exists():
            logger.bind(module="minigate.registry").info(
                "No registry at {path} — starting empty", path=self.path
            )
            return

        try:
            data = yaml.safe_load(registry_path.read_text(encoding="utf-8")) or {}
            parsed = RegistryFile.model_validate(data)
        except Exception as e:
            logger.bind(module="minigate.registry").warning(
                "Could not read registry {path} ({error}) — treating as empty",
                path=self.path,
                error=str(e),
            )
            return

        self._entries = {entry.key: entry for entry in parsed.tools}
        logger.bind(module="minigate.registry").info(
            "Loaded {count} approved tools from {path}", count=len(self._entries), path=self.path
        )

    def save(self) -> None:
        """Write the registry to disk, sorted so diffs stay reviewable."""
        if self.path is None:
            msg = "Cannot save a registry with no path"
            raise ValueError(msg)

        entries = sorted(self._entries.values(), key=lambda e: (e.server, e.name))
        payload = RegistryFile(version=REGISTRY_VERSION, tools=entries).model_dump()
        registry_path = Path(self.path)
        registry_path.parent.mkdir(parents=True, exist_ok=True)
        registry_path.write_text(
            yaml.safe_dump(payload, sort_keys=False, default_flow_style=False, width=100),
            encoding="utf-8",
        )

    # ── queries ──────────────────────────────────────────────────────

    @property
    def entries(self) -> list[ToolEntry]:
        """Approved entries, sorted by server then name."""
        return sorted(self._entries.values(), key=lambda e: (e.server, e.name))

    def get(self, server: str, name: str) -> ToolEntry | None:
        return self._entries.get((server, name))

    def verdict(self, server: str, tool: dict[str, Any]) -> RegistryVerdict:
        """Classify a tool definition the server is advertising."""
        entry = self._entries.get((server, tool.get("name", "")))
        if entry is None:
            return RegistryVerdict.UNKNOWN
        return RegistryVerdict.APPROVED if entry.hash == canonical_hash(tool) else RegistryVerdict.CHANGED

    def is_known(self, server: str, name: str) -> bool:
        """Whether a tool name has ever been approved, regardless of its current definition."""
        return (server, name) in self._entries

    # ── mutation ─────────────────────────────────────────────────────

    def approve(self, server: str, tool: dict[str, Any], approved_by: str = "unknown") -> ToolEntry:
        """Approve a tool definition as advertised, replacing any prior approval."""
        entry = ToolEntry(
            server=server,
            name=tool.get("name", ""),
            hash=canonical_hash(tool),
            approved_at=datetime.now(UTC).isoformat(),
            approved_by=approved_by,
            definition=tool,
        )
        self._entries[entry.key] = entry
        return entry

    def revoke(self, server: str, name: str) -> bool:
        """Remove an approval. Returns whether anything was removed."""
        return self._entries.pop((server, name), None) is not None

    def diff(self, server: str, tools: list[dict[str, Any]]) -> dict[str, list[str]]:
        """Compare advertised tools against what is approved.

        Returns:
            A mapping with 'new', 'changed', 'unchanged', and 'missing' tool names,
            where 'missing' is approved but no longer advertised.
        """
        advertised = {t.get("name", ""): t for t in tools}
        approved = {name for (srv, name) in self._entries if srv == server}

        new, changed, unchanged = [], [], []
        for name, tool in advertised.items():
            verdict = self.verdict(server, tool)
            if verdict == RegistryVerdict.UNKNOWN:
                new.append(name)
            elif verdict == RegistryVerdict.CHANGED:
                changed.append(name)
            else:
                unchanged.append(name)

        return {
            "new": sorted(new),
            "changed": sorted(changed),
            "unchanged": sorted(unchanged),
            "missing": sorted(approved - set(advertised)),
        }
