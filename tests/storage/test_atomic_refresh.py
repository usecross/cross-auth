"""Session refresh must not revive rows that stopped being active."""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlmodel import Session

from .models import SessionStore
from . import test_atomic_signup
from .test_postgres import pg_engine  # noqa: F401

signup_engine = test_atomic_signup.signup_engine

NOW = datetime(2026, 6, 6, 12, tzinfo=timezone.utc)


@pytest.fixture
def refresh_store(signup_engine):
    return SessionStore(session_factory=lambda: Session(signup_engine))


def create(store, *, expires_at):
    return store.create(
        token_hash=uuid.uuid4().hex,
        user_id=uuid.uuid4().hex,
        created_at=NOW - timedelta(hours=2),
        updated_at=NOW - timedelta(hours=1),
        expires_at=expires_at,
        last_active_at=NOW - timedelta(hours=1),
    )


@pytest.mark.parametrize("offset", [-1, 0, 1])
def test_refresh_requires_active_session_at_updated_at(refresh_store, offset):
    store = refresh_store
    original = create(store, expires_at=NOW + timedelta(microseconds=offset))

    refreshed = store.refresh(
        original.id,
        updated_at=NOW,
        expires_at=NOW + timedelta(days=1),
        last_active_at=NOW,
    )

    persisted = store.get_any(original.id)
    if offset < 0:
        assert refreshed is None
        assert persisted.updated_at == original.updated_at
        assert persisted.expires_at == original.expires_at
        assert persisted.last_active_at == original.last_active_at
    else:
        assert refreshed is not None
        assert refreshed.updated_at == persisted.updated_at == NOW
        assert refreshed.expires_at == persisted.expires_at == NOW + timedelta(days=1)
        assert refreshed.last_active_at == persisted.last_active_at == NOW


@pytest.mark.parametrize("bulk", [False, True])
def test_revocation_after_lookup_prevents_refresh(refresh_store, signup_engine, bulk):
    store = refresh_store
    original = create(store, expires_at=NOW + timedelta(hours=1))
    loaded = store.get(token_hash=original.token_hash, now=NOW)
    assert loaded is not None

    other_request = SessionStore(session_factory=lambda: Session(signup_engine))
    if bulk:
        other_request.revoke_all_for_user(original.user_id, revoked_at=NOW)
    else:
        other_request.revoke(original.id, revoked_at=NOW)

    refreshed = store.refresh(
        loaded.id,
        updated_at=NOW,
        expires_at=NOW + timedelta(days=1),
        last_active_at=NOW,
    )

    assert refreshed is None
    persisted = store.get_any(original.id)
    assert persisted.revoked_at == NOW
    assert persisted.updated_at == original.updated_at
    assert persisted.expires_at == original.expires_at
    assert persisted.last_active_at == original.last_active_at
