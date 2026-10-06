"""Environment substitution in minigate.yaml.

A hosted deployment gets its public URL and database from the platform, not from a file
baked into the image — one image, many deployments. These tests pin the behaviour that
makes that safe: an unset variable is a startup error, not an empty string.
"""

from __future__ import annotations

import pytest

from minigate.config import ConfigError, load_config

BASE = """
client_id: test
http:
  public_url: {public_url}
servers:
  linear:
    url: https://mcp.linear.app/mcp
    authorization_servers: ["https://mcp.linear.app"]
"""


def write(tmp_path, public_url: str):
    path = tmp_path / "minigate.yaml"
    path.write_text(BASE.format(public_url=public_url), encoding="utf-8")
    return str(path)


def test_expands_a_set_variable(tmp_path, monkeypatch):
    monkeypatch.setenv("PUBLIC_URL", "https://acme.mcp.stridemap.ai")
    config = load_config(write(tmp_path, "${PUBLIC_URL}"))
    assert config.http.public_url == "https://acme.mcp.stridemap.ai"


def test_uses_the_default_when_unset(tmp_path, monkeypatch):
    monkeypatch.delenv("PUBLIC_URL", raising=False)
    config = load_config(write(tmp_path, "${PUBLIC_URL:-http://127.0.0.1:8787}"))
    assert config.http.public_url == "http://127.0.0.1:8787"


def test_an_unset_variable_with_no_default_is_an_error(tmp_path, monkeypatch):
    """The failure that matters. Substituting "" would bring the gateway up advertising
    an empty public_url, and OAuth discovery would hand clients a URL they cannot reach —
    surfacing as a client-side auth loop far from its cause."""
    monkeypatch.delenv("PUBLIC_URL", raising=False)
    with pytest.raises(ConfigError, match="PUBLIC_URL"):
        load_config(write(tmp_path, "${PUBLIC_URL}"))


def test_every_missing_name_is_reported_at_once(tmp_path, monkeypatch):
    """Fixing one variable per restart is a bad way to configure a deployment."""
    for name in ("ONE", "TWO"):
        monkeypatch.delenv(name, raising=False)
    path = tmp_path / "minigate.yaml"
    path.write_text(
        'client_id: "${ONE}"\nhttp:\n  public_url: "${TWO}"\n', encoding="utf-8"
    )
    with pytest.raises(ConfigError) as excinfo:
        load_config(str(path))
    assert "ONE" in str(excinfo.value)
    assert "TWO" in str(excinfo.value)


def test_a_config_without_variables_is_untouched(tmp_path, monkeypatch):
    """Regression guard: the expansion must not disturb ordinary configs, and a literal
    dollar in a policy path or URL is not a reference."""
    path = tmp_path / "minigate.yaml"
    path.write_text(
        'client_id: plain\nhttp:\n  public_url: "https://example.test/a$b"\n',
        encoding="utf-8",
    )
    config = load_config(str(path))
    assert config.client_id == "plain"
    assert config.http.public_url == "https://example.test/a$b"
