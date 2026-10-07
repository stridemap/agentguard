"""Dependencies the gateway cannot start without.

The test suite runs in a developer environment where transitive and
incidentally-installed packages are present, so an undeclared dependency passes every
test and then crashes the container at startup. That happened: the OAuth endpoints use
FastAPI's Form(), which needs python-multipart, and it was installed locally but never
declared. Route registration failed in the image and the gateway would not boot.

These assert the manifest, not the environment.
"""

from __future__ import annotations

import pathlib
import tomllib

import pytest

PYPROJECT = pathlib.Path(__file__).resolve().parents[2] / "pyproject.toml"


@pytest.fixture(scope="module")
def declared() -> list[str]:
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    return [d.lower() for d in data["project"]["dependencies"]]


@pytest.mark.parametrize(("package", "why"), [
    ("python-multipart", "FastAPI Form() — the OAuth token and revocation endpoints"),
    ("fastapi", "the HTTP gateway"),
    ("httpx", "the upstream client"),
    ("uvicorn", "serving the gateway"),
    ("pydantic", "config and event models"),
    ("pyyaml", "config, policy and registry files"),
])
def test_runtime_dependency_is_declared(declared, package, why):
    assert any(d.startswith(package) for d in declared), (
        f"{package} is required for {why} but is not declared in pyproject.toml. "
        f"It may be installed locally and absent from the built image."
    )


def test_the_oauth_endpoints_really_do_need_multipart():
    """Guards the reason: if Form() is ever dropped, this test should be revisited."""
    source = (PYPROJECT.parent / "minigate" / "bridge.py").read_text(encoding="utf-8")
    assert "Form(" in source, (
        "bridge.py no longer uses Form(); the python-multipart requirement may be stale"
    )
