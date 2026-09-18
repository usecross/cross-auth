"""Contracts for the shared model bases and application-owned schema fields."""

from datetime import datetime, timedelta, timezone
from typing import assert_type

import pytest
from sqlmodel import Session

from cross_auth.storage.sqlmodel import SQLModelSessionStorage

from .models import AliasedVerifiedUser, LeanSocialAccount, UserSession


def test_inherited_session_fields_roundtrip(engine):
    storage = SQLModelSessionStorage(
        UserSession, session_factory=lambda: Session(engine)
    )
    now = datetime.now(timezone.utc)

    created = storage.create(
        token_hash="inherited-fields",
        user_id="user-1",
        created_at=now,
        updated_at=now,
        expires_at=now + timedelta(days=1),
    )
    loaded = storage.get(token_hash="inherited-fields", now=now)

    assert_type(created, UserSession)
    assert_type(loaded, UserSession | None)
    assert loaded is not None
    assert loaded.id == created.id
    assert loaded.created_at == now
    assert loaded.status == "active"
    assert loaded.revoked_at is None
    assert loaded.client_name is None


def test_application_properties_do_not_become_columns():
    assert "email_verified" not in AliasedVerifiedUser.model_fields
    assert "access_token" not in LeanSocialAccount.model_fields
    assert "scope" not in LeanSocialAccount.model_fields

    user = AliasedVerifiedUser(email="test@example.com", full_name="Test")
    user.email_verified = True

    assert user.is_verified is True
    assert user.email_verified is True


def test_session_model_requires_base_even_if_attributes_exist(engine):
    legacy = type(
        "LegacySession",
        (),
        dict.fromkeys([*UserSession.model_fields, "status"]),
    )

    class LegacyStorage(SQLModelSessionStorage):
        SessionModel = legacy

    with pytest.raises(TypeError, match="must inherit from SQLModelSession"):
        LegacyStorage(session_factory=lambda: Session(engine))
