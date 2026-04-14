"""Tests for the policy marketplace.

Covers:
- List policy packs by industry
- Search packs by keyword
- Pack preview and rule access
- Install pack to target directory
- Marketplace API endpoints
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agentguard.marketplace import PolicyMarketplace

os.environ["AGENTGUARD_JWT_SECRET"] = "test-secret"
os.environ["AGENTGUARD_ADMIN_KEY"] = "test-admin-key"
os.environ["AGENTGUARD_ANALYST_KEY"] = "test-analyst-key"

MARKETPLACE_DIR = str(Path(__file__).parent.parent / "policies" / "marketplace")


# ── Fixtures ──────────────────────────────────────────────────────────


@pytest.fixture()
def mp():
    return PolicyMarketplace(marketplace_dir=MARKETPLACE_DIR)


@pytest.fixture()
def client(tmp_path):
    import api.main as app_module

    app_module._db_path = str(tmp_path / "mp.db")
    app_module._store = None
    app_module._policy_engine = None
    app_module._policy_path = None

    with TestClient(app_module.app) as c:
        yield c
    app_module._store = None


def get_admin_token(client: TestClient) -> str:
    return client.post("/auth/token", json={"api_key": "test-admin-key"}).json()[
        "access_token"
    ]


def auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ── Marketplace core ─────────────────────────────────────────────────


class TestMarketplaceCore:
    def test_list_packs(self, mp):
        packs = mp.list_packs()
        assert len(packs) >= 5  # finance(2) + healthcare(1) + legal(1) + it(1)

    def test_list_industries(self, mp):
        industries = mp.list_industries()
        assert "finance" in industries
        assert "healthcare" in industries
        assert "legal" in industries
        assert "it" in industries

    def test_get_pack(self, mp):
        pack = mp.get_pack("finance/pci_dss")
        assert pack is not None
        assert pack.pack_id == "finance/pci_dss"
        assert pack.rule_count >= 3

    def test_get_nonexistent_pack(self, mp):
        assert mp.get_pack("nonexistent/pack") is None

    def test_pack_preview(self, mp):
        pack = mp.get_pack("healthcare/hipaa_phi")
        preview = pack.preview()
        assert "healthcare" in preview["industry"].lower()
        assert preview["rule_count"] >= 4
        assert "pack_id" in preview

    def test_pack_rules(self, mp):
        pack = mp.get_pack("it/security_ops")
        rules = pack.rules()
        assert len(rules) >= 4
        assert all("id" in r for r in rules)
        assert all("action" in r for r in rules)

    def test_search_by_keyword(self, mp):
        results = mp.search("PCI")
        assert len(results) >= 1
        assert any("pci" in r.get("pack_id", "").lower() for r in results)

    def test_search_by_industry(self, mp):
        results = mp.search("healthcare")
        assert len(results) >= 1

    def test_search_no_results(self, mp):
        results = mp.search("nonexistent_keyword_xyz")
        assert len(results) == 0

    def test_install_pack(self, mp, tmp_path):
        target = str(tmp_path / "installed")
        result = mp.install_pack("finance/pci_dss", target_dir=target)
        assert result["status"] == "installed"
        assert result["rule_count"] >= 3
        assert (Path(target) / "pci_dss.yaml").exists()

    def test_install_nonexistent(self, mp, tmp_path):
        result = mp.install_pack("missing/pack", target_dir=str(tmp_path))
        assert result["status"] == "error"


# ── Marketplace API ──────────────────────────────────────────────────


class TestMarketplaceAPI:
    def test_list_packs_api(self, client):
        token = get_admin_token(client)
        resp = client.get("/marketplace/packs", headers=auth(token))
        assert resp.status_code == 200
        assert len(resp.json()) >= 5

    def test_list_industries_api(self, client):
        token = get_admin_token(client)
        resp = client.get("/marketplace/industries", headers=auth(token))
        assert resp.status_code == 200
        assert "finance" in resp.json()

    def test_search_api(self, client):
        token = get_admin_token(client)
        resp = client.get("/marketplace/search?q=HIPAA", headers=auth(token))
        assert resp.status_code == 200
        assert len(resp.json()) >= 1

    def test_get_pack_api(self, client):
        token = get_admin_token(client)
        resp = client.get("/marketplace/packs/finance/pci_dss", headers=auth(token))
        assert resp.status_code == 200
        data = resp.json()
        assert "rules" in data
        assert len(data["rules"]) >= 3
