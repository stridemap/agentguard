"""Policy marketplace — community YAML template discovery and installation.

Provides a registry of policy packs organized by industry vertical.
Users can list, search, preview, and install policy packs into their
active policy directory.

Usage:
    from agentguard.marketplace import PolicyMarketplace

    mp = PolicyMarketplace(marketplace_dir="policies/marketplace")
    packs = mp.list_packs()
    mp.install_pack("finance/pci_dss", target_dir="policies/")
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import yaml

from agentguard.logging import logger


class PolicyPack:
    """A single policy pack from the marketplace."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.filename = path.name
        self.industry = path.parent.name
        self.pack_id = f"{self.industry}/{path.stem}"
        self._data: dict[str, Any] | None = None

    def _load(self) -> dict[str, Any]:
        if self._data is None:
            self._data = yaml.safe_load(self.path.read_text(encoding="utf-8")) or {}
        return self._data

    @property
    def rule_count(self) -> int:
        data = self._load()
        return len(data.get("rules", []))

    @property
    def metadata(self) -> dict[str, Any]:
        """Extract metadata from YAML comments (first lines starting with #)."""
        lines = self.path.read_text(encoding="utf-8").split("\n")
        meta: dict[str, str] = {}
        for line in lines:
            line = line.strip()
            if not line.startswith("#"):
                break
            if ":" in line:
                key, val = line.lstrip("# ").split(":", 1)
                meta[key.strip().lower().replace(" ", "_")] = val.strip()
        return meta

    def preview(self) -> dict[str, Any]:
        """Return a preview of the pack without loading all rules."""
        meta = self.metadata
        return {
            "pack_id": self.pack_id,
            "industry": self.industry,
            "filename": self.filename,
            "rule_count": self.rule_count,
            **meta,
        }

    def rules(self) -> list[dict[str, Any]]:
        """Return the full list of rules."""
        return self._load().get("rules", [])


class PolicyMarketplace:
    """Discovery and installation of community policy packs.

    Attributes:
        marketplace_dir: Directory containing industry-organized YAML packs.
    """

    def __init__(self, marketplace_dir: str = "policies/marketplace") -> None:
        self.marketplace_dir = Path(marketplace_dir)

    def list_packs(self) -> list[dict[str, Any]]:
        """List all available policy packs with metadata."""
        packs: list[dict[str, Any]] = []
        if not self.marketplace_dir.exists():
            return packs

        for yaml_file in sorted(self.marketplace_dir.rglob("*.yaml")):
            pack = PolicyPack(yaml_file)
            packs.append(pack.preview())
        return packs

    def list_industries(self) -> list[str]:
        """List available industry verticals."""
        if not self.marketplace_dir.exists():
            return []
        return sorted({d.name for d in self.marketplace_dir.iterdir() if d.is_dir()})

    def get_pack(self, pack_id: str) -> PolicyPack | None:
        """Get a specific pack by ID (e.g. 'finance/pci_dss')."""
        path = self.marketplace_dir / f"{pack_id}.yaml"
        if not path.exists():
            return None
        return PolicyPack(path)

    def search(self, query: str) -> list[dict[str, Any]]:
        """Search packs by keyword in name, description, or industry."""
        query_lower = query.lower()
        results: list[dict[str, Any]] = []
        for pack_info in self.list_packs():
            searchable = " ".join(str(v) for v in pack_info.values()).lower()
            if query_lower in searchable:
                results.append(pack_info)
        return results

    def install_pack(
        self, pack_id: str, target_dir: str = "policies/"
    ) -> dict[str, Any]:
        """Install a policy pack by copying it to the target directory.

        Args:
            pack_id: Pack identifier (e.g. 'finance/pci_dss').
            target_dir: Directory to install the YAML file into.

        Returns:
            Dict with status, pack_id, target_path, rule_count.
        """
        pack = self.get_pack(pack_id)
        if pack is None:
            return {"status": "error", "message": f"Pack not found: {pack_id}"}

        target = Path(target_dir)
        target.mkdir(parents=True, exist_ok=True)
        dest = target / pack.filename

        shutil.copy2(pack.path, dest)

        logger.bind(module="agentguard.marketplace").info(
            "Installed policy pack: {pack} → {dest} ({rules} rules)",
            pack=pack_id,
            dest=str(dest),
            rules=pack.rule_count,
        )

        return {
            "status": "installed",
            "pack_id": pack_id,
            "target_path": str(dest),
            "rule_count": pack.rule_count,
        }
