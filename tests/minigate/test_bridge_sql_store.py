"""The persistent, encrypted grant store.

Run against SQLite; the PostgreSQL path differs only in parameter style and column type.
The properties asserted are the ones a reviewer would ask about: that grants survive a
restart, that what lands on disk is ciphertext, that codes and sessions are single-use
and expire, and that a wrong key cannot read anything.
"""

from __future__ import annotations

import pathlib

import pytest

from minigate.bridge_sql_store import SqlGrantStore, StoreKeyError, generate_key
from minigate.bridge_store import AuthSession, Grant, RegisteredClient
from minigate.oauth_client import TokenSet

UPSTREAM_SECRET = "upstream-access-token-value"
REFRESH_SECRET = "upstream-refresh-token-value"
VERIFIER_SECRET = "the-upstream-pkce-verifier"


@pytest.fixture
def key():
    return generate_key()


@pytest.fixture
def db(tmp_path):
    return str(tmp_path / "grants.db")


@pytest.fixture
def store(db, key):
    s = SqlGrantStore(db, key=key)
    yield s
    s.close()


def _grant(**over) -> Grant:
    base = {
        "grant_id": "g1", "client_id": "cid", "server_name": "vendor",
        "upstream": TokenSet(
            access_token=UPSTREAM_SECRET, token_type="bearer",
            refresh_token=REFRESH_SECRET, expires_in=86400, scope="read write",
        ),
        "code": "the-code", "code_challenge": "chal", "redirect_uri": "https://c.example/cb",
    }
    return Grant(**{**base, **over})


# ── the key ──────────────────────────────────────────────────────────


def test_a_missing_key_refuses_to_start(db, monkeypatch):
    """The one place MiniGate fails closed: it will not store tokens unencrypted."""
    monkeypatch.delenv("MINIGATE_GRANT_KEY", raising=False)
    with pytest.raises(StoreKeyError, match="not set"):
        SqlGrantStore(db)


def test_a_malformed_key_refuses_to_start(db):
    with pytest.raises(StoreKeyError, match="not a valid Fernet key"):
        SqlGrantStore(db, key="not-a-real-key")


def test_the_key_can_come_from_the_environment(db, key, monkeypatch):
    monkeypatch.setenv("MINIGATE_GRANT_KEY", key)
    store = SqlGrantStore(db)
    store.put_grant(_grant())
    store.close()


# ── encryption at rest ───────────────────────────────────────────────


def test_no_upstream_credential_appears_in_the_database_file(store, db):
    """The property that matters for a stolen dump or a backup."""
    store.put_grant(_grant(access_token="our-token"))
    raw = pathlib.Path(db).read_bytes()

    assert UPSTREAM_SECRET.encode() not in raw
    assert REFRESH_SECRET.encode() not in raw
    # Our own token is an index key, so it is stored in the clear by design — it is
    # useless without the sealed row it points at.
    assert b"our-token" in raw


def test_a_session_verifier_is_not_stored_in_the_clear(store, db):
    store.put_session(AuthSession(
        session_id="s1", client_id="cid", server_name="vendor",
        client_redirect_uri="https://c.example/cb", client_state="st",
        client_code_challenge="chal", client_code_challenge_method="S256",
        upstream_verifier=VERIFIER_SECRET,
    ))
    assert VERIFIER_SECRET.encode() not in pathlib.Path(db).read_bytes()


def test_a_different_key_cannot_read_the_grants(db, key):
    first = SqlGrantStore(db, key=key)
    first.put_grant(_grant(access_token="our-token"))
    first.close()

    from cryptography.fernet import InvalidToken

    other = SqlGrantStore(db, key=generate_key())
    with pytest.raises(InvalidToken):
        other.get_by_access_token("our-token")
    other.close()


# ── persistence ──────────────────────────────────────────────────────


def test_grants_survive_a_restart(db, key):
    """The whole point: a deploy must not log everyone out."""
    first = SqlGrantStore(db, key=key)
    first.put_grant(_grant(access_token="our-token"))
    first.close()

    second = SqlGrantStore(db, key=key)
    found = second.get_by_access_token("our-token")
    assert found is not None
    assert found.upstream.access_token == UPSTREAM_SECRET
    assert found.upstream.refresh_token == REFRESH_SECRET
    assert found.upstream.authorization_header == f"Bearer {UPSTREAM_SECRET}"
    second.close()


def test_clients_survive_a_restart(db, key):
    first = SqlGrantStore(db, key=key)
    first.put_client(RegisteredClient(
        client_id="cid", redirect_uris=("https://c.example/cb",), client_name="Claude"))
    first.close()

    second = SqlGrantStore(db, key=key)
    client = second.get_client("cid")
    assert client is not None
    assert client.redirect_uris == ("https://c.example/cb",)
    assert client.allows("https://c.example/cb")
    assert not client.allows("https://evil.example/cb")
    second.close()


# ── single use and expiry ────────────────────────────────────────────


def test_an_authorization_code_is_single_use(store):
    store.put_grant(_grant())
    assert store.take_by_code("the-code") is not None
    assert store.take_by_code("the-code") is None


def test_an_expired_code_is_refused(store):
    store.put_grant(_grant(created_at=0.0))
    assert store.take_by_code("the-code") is None


def test_a_session_is_single_use(store):
    store.put_session(AuthSession(
        session_id="s1", client_id="c", server_name="v",
        client_redirect_uri="https://c.example/cb", client_state=None,
        client_code_challenge=None, client_code_challenge_method="S256",
        upstream_verifier="v",
    ))
    assert store.take_session("s1") is not None
    assert store.take_session("s1") is None


def test_an_expired_session_is_refused(store):
    store.put_session(AuthSession(
        session_id="old", client_id="c", server_name="v",
        client_redirect_uri="https://c.example/cb", client_state=None,
        client_code_challenge=None, client_code_challenge_method="S256",
        upstream_verifier="v", created_at=0.0,
    ))
    assert store.take_session("old") is None


def test_a_session_round_trips_every_field(store):
    store.put_session(AuthSession(
        session_id="s1", client_id="cid", server_name="vendor",
        client_redirect_uri="https://c.example/cb", client_state="client-state",
        client_code_challenge="chal", client_code_challenge_method="S256",
        upstream_verifier=VERIFIER_SECRET,
    ))
    s = store.take_session("s1")
    assert s is not None
    assert s.upstream_verifier == VERIFIER_SECRET
    assert s.client_state == "client-state"
    assert s.server_name == "vendor"


# ── revocation and cleanup ───────────────────────────────────────────


def test_revoking_removes_the_grant(store):
    store.put_grant(_grant(access_token="our-token"))
    assert store.revoke("our-token") is True
    assert store.get_by_access_token("our-token") is None
    assert store.revoke("our-token") is False


def test_issuing_a_token_updates_the_existing_grant(store):
    """The code is cleared and the access token set on the same row, not a second one."""
    store.put_grant(_grant())
    grant = store.take_by_code("the-code")
    assert grant is not None

    grant.code = None
    grant.access_token = "issued"
    store.put_grant(grant)

    assert store.counts["grants"] == 1
    assert store.get_by_access_token("issued") is not None


def test_abandoned_sessions_are_purged(store, monkeypatch):
    """A credential nothing can use is liability, not state."""
    store.put_session(AuthSession(
        session_id="stale", client_id="c", server_name="v",
        client_redirect_uri="https://c.example/cb", client_state=None,
        client_code_challenge=None, client_code_challenge_method="S256",
        upstream_verifier="v", created_at=0.0,
    ))
    assert store.counts["sessions"] == 1

    store._last_purge = 0.0          # allow the next call to purge
    store.put_client(RegisteredClient(client_id="x", redirect_uris=("https://c.example/cb",)))
    assert store.counts["sessions"] == 0
