"""PostgreSQL integration tests for the SQLModel storage adapters.

These run against a disposable Postgres container (testcontainers) whose
connection TimeZone is deliberately non-UTC: that is the configuration that
exposes naive/aware datetime handling and parameter-typing bugs SQLite cannot
reproduce (SQLite stores datetimes as strings and coerces text ids silently).
The tests skip automatically when Docker is unavailable.
"""

import base64
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import cast

import pytest
from sqlmodel import Session, SQLModel, create_engine

from cross_auth._session import create_session, get_session
from cross_auth._storage import SessionStorage
from cross_auth.exceptions import InvalidCursorError

from .models import (
    AccountsStore,
    RenamedColumnSessionStore,
    SessionStore,
    UuidSessionStore,
)

pytest.importorskip("psycopg")
testcontainers_postgres = pytest.importorskip("testcontainers.postgres")


@pytest.fixture(scope="module")
def pg_engine():
    try:
        container = testcontainers_postgres.PostgresContainer(
            "postgres:16-alpine", driver="psycopg"
        )
        container.start()
    except Exception as exc:  # docker missing or unreachable
        # In CI, Docker must be available; skipping silently would hide a
        # broken test environment instead of failing the build.
        if os.environ.get("CI"):
            raise
        pytest.skip(f"Docker unavailable for testcontainers: {exc}")
    engine = create_engine(
        container.get_connection_url(),
        # A non-UTC connection TimeZone is what breaks naive-datetime
        # handling in production; keep it weird on purpose.
        connect_args={"options": "-c TimeZone=America/New_York"},
    )
    SQLModel.metadata.create_all(engine)
    yield engine
    engine.dispose()
    container.stop()


@pytest.fixture
def store(pg_engine):
    return SessionStore(session_factory=lambda: Session(pg_engine))


@pytest.fixture
def accounts(pg_engine):
    return AccountsStore(session_factory=lambda: Session(pg_engine))


@pytest.fixture
def uuid_store(pg_engine):
    return UuidSessionStore(session_factory=lambda: Session(pg_engine))


def _uid() -> str:
    return f"u-{uuid.uuid4().hex[:12]}"


def _make(store, *, user_id, suffix="0", now, **overrides):
    values = {
        "token_hash": f"{user_id}-t{suffix}",
        "user_id": user_id,
        "created_at": now,
        "updated_at": now,
        "expires_at": now + timedelta(days=1),
        **overrides,
    }
    return store.create(**values)


def test_roundtrip_preserves_utc_instants(store):
    user_id = _uid()
    now = datetime.now(tz=timezone.utc)

    record = store.create(
        token_hash=f"{user_id}-th",
        user_id=user_id,
        created_at=now,
        updated_at=now,
        expires_at=now + timedelta(days=1),
        last_active_at=now,
    )
    fetched = store.get(token_hash=f"{user_id}-th", now=now)

    assert fetched is not None
    # The exact instants survive the non-UTC connection TimeZone; a shifted
    # value here is the bug that broke sliding refresh and reported expiry.
    assert fetched.created_at == now
    assert fetched.updated_at == now
    assert fetched.last_active_at == now
    assert fetched.expires_at == now + timedelta(days=1)
    assert fetched.updated_at.tzinfo is not None

    new_updated = now + timedelta(hours=1)
    new_expires = now + timedelta(days=2)
    store.refresh(
        record.id,
        updated_at=new_updated,
        expires_at=new_expires,
        last_active_at=new_updated,
    )

    # Re-read through a fresh session on the same non-UTC connection: the
    # refresh must have been committed and the instants must survive intact.
    persisted = store.get_any(record.id)
    assert persisted is not None
    assert persisted.updated_at == new_updated
    assert persisted.expires_at == new_expires
    assert persisted.last_active_at == new_updated


def test_core_sliding_refresh_window_arithmetic(store):
    # The core decides whether to roll a session via `now - updated_at`.
    # Within the update window nothing must be refreshed; a timezone shift of
    # the stored value makes this fire on every request (or never).
    session_storage = cast(SessionStorage, store)
    token, record = create_session(_uid(), session_storage)

    session = get_session(token, session_storage, {"update_age": 3600})

    assert session is not None
    assert session.updated_at == record.updated_at


def test_cursor_pagination_walks_all_pages(store):
    user_id = _uid()
    now = datetime.now(tz=timezone.utc)
    for i in range(5):
        _make(
            store,
            user_id=user_id,
            suffix=str(i),
            now=now,
            updated_at=now + timedelta(minutes=i),
        )

    seen: list[str] = []
    cursor = None
    for _ in range(5):
        page = store.list_for_user(user_id, now=now, limit=2, cursor=cursor)
        seen.extend(r.token_hash for r in page.records)
        cursor = page.next_cursor
        if cursor is None:
            break

    # No rows skipped or duplicated across the cursor boundary.
    assert seen == [f"{user_id}-t{i}" for i in (4, 3, 2, 1, 0)]


def test_status_filters(store):
    user_id = _uid()
    now = datetime.now(tz=timezone.utc)
    active = _make(store, user_id=user_id, suffix="active", now=now)
    expired = _make(
        store,
        user_id=user_id,
        suffix="expired",
        now=now,
        expires_at=now - timedelta(seconds=1),
    )
    revoked = _make(store, user_id=user_id, suffix="revoked", now=now)
    store.revoke(revoked.id, revoked_at=now)

    by_status = {
        status: [
            r.id for r in store.list_for_user(user_id, now=now, status=status).records
        ]
        for status in ("active", "expired", "revoked")
    }

    assert by_status == {
        "active": [active.id],
        "expired": [expired.id],
        "revoked": [revoked.id],
    }


def test_string_ids_match_int_pk_instead_of_erroring(store, accounts):
    user_id = _uid()
    now = datetime.now(tz=timezone.utc)
    record = _make(store, user_id=user_id, now=now)

    # HTTP path params arrive as strings; without coercion Postgres raises
    # DataError ("invalid input syntax for type ...") instead of matching.
    assert store.get_any(str(record.id)) is not None
    assert store.get_any("abc") is None
    store.revoke("abc", revoked_at=now)  # no-op, not a 500

    user = accounts.create_user(
        user_info={}, email=f"{user_id}@example.com", email_verified=True
    )
    assert accounts.find_user_by_id(str(user.id)) is not None
    assert accounts.find_user_by_id("abc") is None
    assert accounts.find_social_account_by_id("abc") is None


def test_session_user_id_string_column_matches_core_usage(store):
    # Core always passes user ids as str (login(user_id: str)); the documented
    # session model declares user_id: str so inserts and filters type-match.
    user_id_as_core_sends_it = str(12345)
    now = datetime.now(tz=timezone.utc)
    record = _make(store, user_id=user_id_as_core_sends_it, now=now)

    result = store.list_for_user(user_id_as_core_sends_it, now=now)
    assert [r.id for r in result.records] == [record.id]


def test_social_account_token_expiry_roundtrips_aware(accounts):
    user = accounts.create_user(
        user_info={}, email=f"{_uid()}@example.com", email_verified=True
    )
    expires = datetime.now(tz=timezone.utc) + timedelta(hours=1)

    account = accounts.create_social_account(
        user_id=user.id,
        provider="github",
        provider_user_id=_uid(),
        access_token="at",
        refresh_token=None,
        access_token_expires_at=expires,
        refresh_token_expires_at=None,
        scope=None,
        user_info={},
        provider_email=None,
        provider_email_verified=None,
        is_login_method=True,
    )

    fetched = accounts.find_social_account_by_id(account.id)
    assert fetched.access_token_expires_at == expires
    assert fetched.access_token_expires_at.tzinfo is not None


def test_renamed_columns_preserve_utc_on_non_utc_connection(pg_engine):
    # Renamed naive datetime columns must still be stored as UTC wall time on a
    # non-UTC connection. Resolving the column by its database name instead of
    # its attribute would skip tz-stripping and silently shift every instant.
    store = RenamedColumnSessionStore(session_factory=lambda: Session(pg_engine))
    user_id = _uid()
    now = datetime.now(tz=timezone.utc)
    store.create(
        token_hash=f"{user_id}-rt",
        user_id=user_id,
        created_at=now,
        updated_at=now,
        expires_at=now + timedelta(days=1),
        last_active_at=now,
    )

    fetched = store.get(token_hash=f"{user_id}-rt", now=now)

    assert fetched is not None
    assert fetched.created_at == now
    assert fetched.last_active_at == now
    assert fetched.expires_at == now + timedelta(days=1)


def test_revoke_all_reports_rowcount(store):
    user_id = _uid()
    now = datetime.now(tz=timezone.utc)
    _make(store, user_id=user_id, suffix="a", now=now)
    _make(store, user_id=user_id, suffix="b", now=now)

    assert store.revoke_all_for_user(user_id, revoked_at=now) == 2
    assert store.revoke_all_for_user(user_id, revoked_at=now) == 0


def _crafted_cursor(order_by: str, now: datetime, row_id: object) -> str:
    payload = {"o": order_by, "v": now.isoformat(), "id": row_id}
    return base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()


def test_crafted_cross_type_cursor_ids_raise_invalid_cursor(store, uuid_store):
    # Without coercion these reach Postgres as `integer < uuid` and
    # `uuid < integer` respectively, raising ProgrammingError instead of the
    # documented InvalidCursorError.
    user_id = _uid()
    now = datetime.now(tz=timezone.utc)
    _make(store, user_id=user_id, now=now)
    uuid_shaped_id = {"t": "uuid", "v": str(uuid.uuid4())}
    crafted = _crafted_cursor("updated_at_desc", now, uuid_shaped_id)

    with pytest.raises(InvalidCursorError):
        store.list_for_user(user_id, now=now, cursor=crafted)

    uuid_store.create(
        token_hash=f"{user_id}-uuid",
        user_id=user_id,
        created_at=now,
        updated_at=now,
        expires_at=now + timedelta(days=1),
    )
    crafted_int = _crafted_cursor("updated_at_desc", now, 1)

    with pytest.raises(InvalidCursorError):
        uuid_store.list_for_user(user_id, now=now, cursor=crafted_int)


def test_get_any_out_of_range_id_returns_none_instead_of_data_error(store):
    # int("99999999999") comfortably exceeds a Postgres int4 primary key,
    # which previously raised DataError (NumericValueOutOfRange) instead of
    # answering None.
    assert store.get_any("99999999999") is None
