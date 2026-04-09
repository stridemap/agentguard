"""Shared test fixtures for AgentGuard test suite."""

from __future__ import annotations

import pytest


@pytest.fixture()
def tmp_db(tmp_path):
    """Return a temporary SQLite database path for test isolation."""
    return str(tmp_path / "test_agentguard.db")
