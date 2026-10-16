"""Configuration loading.

The gateway's behaviour is entirely determined by this file, so a config that loads
successfully must mean what it says. An unknown key is the dangerous case: silently
dropping it leaves a control switched off with nothing to distinguish that from intent.
"""

from __future__ import annotations

import pytest

from minigate.config import ConfigError, load_config

# ── unknown keys are a configuration error ───────────────────────────
#
# A typo in a security-relevant key would otherwise start a gateway that silently
# governs nothing: the key is dropped, the field takes its default, and nothing
# distinguishes that from a deliberate choice.


def _write(tmp_path, body: str):
    path = tmp_path / "c.yaml"
    path.write_text(body, encoding="utf-8")
    return str(path)


BASE = """
http: {public_url: "http://x"}
servers: {linear: {url: "https://mcp.linear.app/mcp"}}
"""


def test_a_mistyped_policy_key_is_rejected(tmp_path):
    """Silently defaulting here means no policy is loaded and every call is permitted."""
    with pytest.raises(ConfigError, match="policyy"):
        load_config(_write(tmp_path, BASE + "policyy: policies/minigate.yaml\n"))


def test_a_mistyped_registry_key_is_rejected(tmp_path):
    """Silently defaulting here turns definition pinning off."""
    with pytest.raises(ConfigError, match="registryy"):
        load_config(
            _write(tmp_path, BASE + "registryy: {path: r.yaml, mode: enforce}\n")
        )


def test_an_unknown_key_in_a_nested_section_is_rejected(tmp_path):
    with pytest.raises(ConfigError, match="requiree"):
        load_config(
            _write(
                tmp_path,
                """
http:
  public_url: "http://x"
  auth: {mode: bridge, requiree: true}
servers: {linear: {url: "https://mcp.linear.app/mcp"}}
""",
            )
        )


def test_an_unknown_key_on_a_server_is_rejected(tmp_path):
    with pytest.raises(ConfigError, match="urll"):
        load_config(
            _write(
                tmp_path,
                """
http: {public_url: "http://x"}
servers: {linear: {urll: "https://mcp.linear.app/mcp"}}
""",
            )
        )


def test_a_correct_config_still_loads(tmp_path):
    config = load_config(_write(tmp_path, BASE + "database_url: audit.db\n"))
    assert config.database_url.endswith("audit.db")
    assert "linear" in config.servers
