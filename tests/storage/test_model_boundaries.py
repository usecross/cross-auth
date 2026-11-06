"""Application model capabilities and atomic transaction participation."""

from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
from typing import assert_type

import pytest
from sqlalchemy import create_engine, event
from sqlmodel import Session

from .models import (
    AccountsStore,
    PropertyExpiryAccountsStore,
    PropertyExpirySocialAccount,
    SignupApplicationRow,
    SocialAccount,
    User,
)
from .support import identity_data, user_data

NOW = datetime(2026, 6, 6, 12, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    "binding",
    [
        "different_engines",
        "different_connections",
        "engine_and_connection",
        "application_row",
    ],
)
def test_atomic_signup_rejects_split_binds_before_construction_or_sql(engine, binding):
    class GuardedBuilder(AccountsStore):
        def build_user(self, *, session, **kwargs):
            if binding != "application_row":
                pytest.fail("Split configured binds must fail before construction")
            user = super().build_user(session=session, **kwargs)
            # The relationship supplies user_id when the adapter flushes.
            session.add(
                SignupApplicationRow(
                    user=user, label="split"
                )  # ty: ignore[missing-argument]
            )
            return user

    statements = []

    def record_sql(connection, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    with ExitStack() as stack:
        other_engine = create_engine("sqlite://")
        stack.callback(other_engine.dispose)
        for candidate in (engine, other_engine):
            event.listen(candidate, "before_cursor_execute", record_sql)
            stack.callback(event.remove, candidate, "before_cursor_execute", record_sql)
        if binding == "application_row":
            first = second = engine
        elif binding == "different_engines":
            first, second = engine, other_engine
        elif binding == "different_connections":
            first = stack.enter_context(engine.connect())
            second = stack.enter_context(engine.connect())
        else:
            first = engine
            second = stack.enter_context(engine.connect())
        store = GuardedBuilder(
            session_factory=lambda: Session(
                binds={
                    User: first,
                    SocialAccount: second,
                    SignupApplicationRow: other_engine,
                }
            )
        )
        with pytest.raises(RuntimeError, match="same transactional bind"):
            store.create_user_with_identity(
                user=user_data("split@example.com"),
                identity=lambda user: identity_data(user, "split"),
            )
    assert statements == []


@pytest.mark.parametrize("atomic", [False, True])
def test_legacy_builder_override_still_serves_both_creation_apis(engine, atomic):
    class LegacyBuilder(AccountsStore):
        def _build_user(self, *, session, **kwargs):
            user = super()._build_user(session=session, **kwargs)
            user.hashed_password = "legacy-builder"
            return user

    store = LegacyBuilder(session_factory=lambda: Session(engine))
    data = user_data("legacy@example.com")
    if atomic:
        user, account = store.create_user_with_identity(
            user=data, identity=lambda user: identity_data(user, "legacy")
        )
        assert account.user_id == user.id
    else:
        user = store.create_user(**data)
    assert user.hashed_password == "legacy-builder"
    loaded = store.find_user_by_id(user.id)
    assert loaded is not None
    assert loaded.hashed_password == "legacy-builder"


@pytest.fixture
def property_account(
    engine,
) -> tuple[PropertyExpiryAccountsStore, PropertyExpirySocialAccount]:
    store = PropertyExpiryAccountsStore(session_factory=lambda: Session(engine))
    user = store.create_user(**user_data("property@example.com"))
    data = identity_data(user, "property-expiry")
    data["extra_fields"] = {
        "stored_access_expiry": NOW,
        "stored_refresh_expiry": NOW + timedelta(days=1),
    }
    account = store.create_social_account(**data)
    return store, account


def test_property_backed_timestamps_own_their_aware_conversion(
    property_account: tuple[PropertyExpiryAccountsStore, PropertyExpirySocialAccount],
):
    store, created = property_account
    assert_type(created, PropertyExpirySocialAccount)
    loaded = store.find_social_account_by_id(created.id)
    assert_type(loaded, PropertyExpirySocialAccount | None)
    assert loaded is not None
    assert loaded.access_token_expires_at == NOW
    assert loaded.refresh_token_expires_at == NOW + timedelta(days=1)
    assert loaded.stored_access_expiry is not None
    assert loaded.stored_refresh_expiry is not None
    assert loaded.stored_access_expiry.tzinfo is None
    assert loaded.stored_refresh_expiry.tzinfo is None


def test_property_timestamp_validation_precedes_signup_commit(engine, monkeypatch):
    store = PropertyExpiryAccountsStore(session_factory=lambda: Session(engine))
    monkeypatch.setattr(
        PropertyExpirySocialAccount,
        "access_token_expires_at",
        property(lambda account: account.stored_access_expiry),
    )

    def identity(user):
        data = identity_data(user, "invalid-property")
        data["extra_fields"] = {"stored_access_expiry": NOW}
        return data

    with pytest.raises(TypeError, match="access_token_expires_at.*timezone-aware"):
        store.create_user_with_identity(
            user=user_data("invalid-property@example.com"), identity=identity
        )
    assert store.find_user_by_email("invalid-property@example.com") is None


@pytest.mark.parametrize(
    "field", ["access_token_expires_at", "refresh_token_expires_at"]
)
def test_naive_read_only_timestamp_has_a_clear_model_contract_error(
    property_account, monkeypatch, field
):
    store, created = property_account
    properties = {
        "access_token_expires_at": property(
            lambda account: account.stored_access_expiry
        ),
        "refresh_token_expires_at": property(
            lambda account: account.stored_refresh_expiry
        ),
    }
    monkeypatch.setattr(PropertyExpirySocialAccount, field, properties[field])
    with pytest.raises(TypeError, match=f"{field}.*timezone-aware"):
        store.find_social_account_by_id(created.id)
