"""DjangoSessionStorage against Cross Auth's SessionStorage contract.

Most tests here follow ``tests/storage/test_sqlmodel_session.py``,
``test_atomic_refresh.py`` and ``test_record_activity.py``, which hold the
SQLModel storage to the same contract. The last ones cover what is Django's
own: the table is shared with browser sessions.
"""

from __future__ import annotations

import base64
import json
import logging
import uuid
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
import time_machine
from django.conf import settings
from django.contrib.auth.base_user import AbstractBaseUser
from django.core.management import call_command
from django.db import OperationalError, connection, transaction
from django.test import Client, override_settings

from cross_auth._session import create_session, get_session
from cross_auth._storage import (
    SessionActivityStorage,
    SessionListOrder,
    SessionStorage,
)
from cross_auth.django.models import Session
from cross_auth.django.sessions import SessionStore
from cross_auth.django.storage import DjangoSessionRecord, DjangoSessionStorage
from cross_auth.storage import InvalidCursorError

from .support import make_user

pytestmark = pytest.mark.django_db

NOW = datetime(2026, 6, 6, 12, 0, 0, tzinfo=timezone.utc)
EARLIER = NOW - timedelta(hours=1)
SINCE = NOW - timedelta(minutes=5)


@pytest.fixture
def store() -> DjangoSessionStorage:
    return DjangoSessionStorage()


@pytest.fixture
def user() -> AbstractBaseUser:
    return make_user("u1@example.com")


@pytest.fixture
def other() -> AbstractBaseUser:
    return make_user("u2@example.com")


def _make(
    store: DjangoSessionStorage,
    user: AbstractBaseUser,
    *,
    token_hash: str = "hash",
    created: datetime = NOW,
    updated: datetime = NOW,
    expires: datetime | None = None,
    last_active: datetime | None = None,
) -> DjangoSessionRecord:
    return store.create(
        token_hash=token_hash,
        user_id=str(user.pk),
        created_at=created,
        updated_at=updated,
        expires_at=expires or (NOW + timedelta(days=1)),
        last_active_at=last_active,
    )


def _hashes(records: list[DjangoSessionRecord]) -> list[str | None]:
    return [record.native.token_hash for record in records]


def test_implements_the_storage_protocols(store: DjangoSessionStorage) -> None:
    # A static check: the storage must fit where core takes a SessionStorage.
    session_storage: SessionStorage = store

    assert session_storage is store
    assert isinstance(store, SessionActivityStorage)


@time_machine.travel(NOW)
def test_create_returns_usable_record(
    store: DjangoSessionStorage, user: AbstractBaseUser
) -> None:
    record = store.create(
        token_hash="abc",
        user_id=str(user.pk),
        created_at=NOW,
        updated_at=NOW,
        expires_at=NOW + timedelta(days=1),
        client_id="client",
        client_name="An app",
        user_agent="Agent",
        ip="203.0.113.7",
        last_active_at=NOW,
        login_method="google",
    )

    assert isinstance(record.id, uuid.UUID)
    assert record.id == record.native.public_id
    assert record.user_id == user.pk
    assert record.created_at == record.updated_at == record.last_active_at == NOW
    assert record.expires_at == NOW + timedelta(days=1)
    assert record.revoked_at is None
    assert (record.client_id, record.client_name) == ("client", "An app")
    assert (record.user_agent, record.ip) == ("Agent", "203.0.113.7")
    assert record.login_method == "google"
    assert record.status == "active"
    assert record.native.token_hash == "abc"


def test_last_activity_starts_at_creation_when_not_given(
    store: DjangoSessionStorage, user: AbstractBaseUser
) -> None:
    record = _make(store, user, created=EARLIER)

    assert record.last_active_at == EARLIER


def test_get_active_by_token_hash(
    store: DjangoSessionStorage, user: AbstractBaseUser
) -> None:
    _make(store, user, token_hash="abc")

    record = store.get(token_hash="abc", now=NOW)

    assert record is not None
    assert record.native.token_hash == "abc"


def test_get_session_with_sliding_refresh(
    store: DjangoSessionStorage, user: AbstractBaseUser
) -> None:
    token, _ = create_session(str(user.pk), store)

    session = get_session(token, store, {"update_age": 0})

    assert session is not None
    assert session.updated_at.tzinfo is not None


def test_get_does_not_return_expired(
    store: DjangoSessionStorage, user: AbstractBaseUser
) -> None:
    _make(store, user, token_hash="abc", expires=NOW - timedelta(seconds=1))

    assert store.get(token_hash="abc", now=NOW) is None


def test_get_active_at_exact_expiry_instant(
    store: DjangoSessionStorage, user: AbstractBaseUser
) -> None:
    # Matches cross_auth.session_status: active up to and including expiry.
    _make(store, user, token_hash="abc", expires=NOW)

    assert store.get(token_hash="abc", now=NOW) is not None


def test_get_does_not_return_revoked(
    store: DjangoSessionStorage, user: AbstractBaseUser
) -> None:
    record = _make(store, user, token_hash="abc")
    store.revoke(record.id, revoked_at=NOW)

    assert store.get(token_hash="abc", now=NOW) is None


def test_get_missing_returns_none(store: DjangoSessionStorage) -> None:
    assert store.get(token_hash="nope", now=NOW) is None


def test_get_any_returns_regardless_of_status(
    store: DjangoSessionStorage, user: AbstractBaseUser
) -> None:
    expired = _make(store, user, token_hash="a", expires=NOW - timedelta(days=1))
    revoked = _make(store, user, token_hash="b")
    store.revoke(revoked.id, revoked_at=NOW)

    assert _status(store, expired.id) == "expired"
    assert _status(store, revoked.id) == "revoked"


def _status(store: DjangoSessionStorage, session_id: object) -> str:
    record = store.get_any(session_id)
    assert record is not None
    with time_machine.travel(NOW, tick=False):
        return record.status


def _stored(store: DjangoSessionStorage, session_id: object) -> DjangoSessionRecord:
    record = store.get_any(session_id)
    assert record is not None
    return record


def test_get_any_missing_returns_none(store: DjangoSessionStorage) -> None:
    assert store.get_any(uuid.uuid4()) is None


def test_get_any_coerces_string_ids(
    store: DjangoSessionStorage, user: AbstractBaseUser
) -> None:
    # Ids arrive as strings from HTTP path params.
    record = _make(store, user)

    assert store.get_any(str(record.id)) is not None
    assert store.get_any("abc") is None


@pytest.mark.parametrize("session_id", [99999, 10**100, "99999999999", None, ""])
def test_an_id_that_is_no_uuid_matches_nothing(
    store: DjangoSessionStorage, user: AbstractBaseUser, session_id: object
) -> None:
    _make(store, user)

    assert store.get_any(session_id) is None
    assert store.refresh(session_id, updated_at=NOW, expires_at=NOW) is None
    assert store.record_activity(session_id, last_active_at=NOW, since=SINCE) is None
    assert store.revoke(session_id, revoked_at=NOW) is False


def test_refresh_updates_timestamps(
    store: DjangoSessionStorage, user: AbstractBaseUser
) -> None:
    record = _make(store, user)
    new_updated = NOW + timedelta(hours=1)
    new_expires = NOW + timedelta(days=2)

    refreshed = store.refresh(
        record.id,
        updated_at=new_updated,
        expires_at=new_expires,
        last_active_at=new_updated,
    )

    assert refreshed is not None
    assert refreshed.updated_at == new_updated
    assert refreshed.expires_at == new_expires
    persisted = _stored(store, record.id)
    assert persisted.updated_at == new_updated
    assert persisted.expires_at == new_expires
    assert persisted.last_active_at == new_updated


def test_refresh_preserves_last_active_at_when_omitted(
    store: DjangoSessionStorage, user: AbstractBaseUser
) -> None:
    record = _make(store, user, last_active=NOW)

    refreshed = store.refresh(
        record.id,
        updated_at=NOW + timedelta(hours=1),
        expires_at=NOW + timedelta(days=2),
    )

    assert refreshed is not None
    assert refreshed.last_active_at == NOW


def test_refresh_missing_returns_none(store: DjangoSessionStorage) -> None:
    assert store.refresh(uuid.uuid4(), updated_at=NOW, expires_at=NOW) is None


def _aged(
    store: DjangoSessionStorage, user: AbstractBaseUser, *, expires_at: datetime
) -> DjangoSessionRecord:
    """A session issued two hours ago and last used an hour ago."""
    return _make(
        store,
        user,
        token_hash=uuid.uuid4().hex,
        created=NOW - timedelta(hours=2),
        updated=EARLIER,
        expires=expires_at,
        last_active=EARLIER,
    )


@pytest.mark.parametrize("offset", [-1, 0, 1])
def test_refresh_requires_active_session_at_updated_at(
    store: DjangoSessionStorage, user: AbstractBaseUser, offset: int
) -> None:
    original = _aged(store, user, expires_at=NOW + timedelta(microseconds=offset))

    refreshed = store.refresh(
        original.id,
        updated_at=NOW,
        expires_at=NOW + timedelta(days=1),
        last_active_at=NOW,
    )

    persisted = _stored(store, original.id)
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
def test_revocation_after_lookup_prevents_refresh(
    store: DjangoSessionStorage, user: AbstractBaseUser, bulk: bool
) -> None:
    original = _aged(store, user, expires_at=NOW + timedelta(hours=1))
    token_hash = original.native.token_hash
    assert token_hash is not None
    loaded = store.get(token_hash=token_hash, now=NOW)
    assert loaded is not None

    other_request = DjangoSessionStorage()
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
    persisted = _stored(store, original.id)
    assert persisted.revoked_at == NOW
    assert persisted.updated_at == original.updated_at
    assert persisted.expires_at == original.expires_at
    assert persisted.last_active_at == original.last_active_at


@pytest.mark.parametrize(
    "stale_by", [timedelta(minutes=5), timedelta(0)], ids=["earlier", "equal"]
)
def test_stale_refresh_does_not_move_the_session_backwards(
    store: DjangoSessionStorage, user: AbstractBaseUser, stale_by: timedelta
) -> None:
    original = _aged(store, user, expires_at=NOW + timedelta(hours=1))
    later = NOW + timedelta(minutes=5)
    store.refresh(
        original.id,
        updated_at=later,
        expires_at=later + timedelta(days=1),
        last_active_at=later,
    )

    # A request that read the session before that refresh commits after it,
    # with an earlier or equal updated_at and a shorter expiry.
    stale_at = later - stale_by
    stale = store.refresh(
        original.id,
        updated_at=stale_at,
        expires_at=stale_at + timedelta(hours=1),
        last_active_at=stale_at,
    )

    persisted = _stored(store, original.id)
    assert stale is not None
    assert stale.updated_at == persisted.updated_at == later
    assert stale.expires_at == persisted.expires_at == later + timedelta(days=1)
    assert stale.last_active_at == persisted.last_active_at == later


def test_delayed_refresh_keeps_a_later_recorded_use(
    store: DjangoSessionStorage, user: AbstractBaseUser
) -> None:
    original = _aged(store, user, expires_at=NOW + timedelta(hours=1))

    # Another request records a use after this one read the session, and
    # commits before this one's refresh, which carries an earlier time.
    assert DjangoSessionStorage().record_activity(
        original.id, last_active_at=NOW + timedelta(seconds=3), since=SINCE
    )
    refreshed = store.refresh(
        original.id,
        updated_at=NOW + timedelta(seconds=2),
        expires_at=NOW + timedelta(days=1),
        last_active_at=NOW + timedelta(seconds=2),
    )

    persisted = _stored(store, original.id)
    assert refreshed is not None
    assert refreshed.updated_at == persisted.updated_at == NOW + timedelta(seconds=2)
    assert refreshed.expires_at == persisted.expires_at == NOW + timedelta(days=1)
    assert (
        refreshed.last_active_at
        == persisted.last_active_at
        == NOW + timedelta(seconds=3)
    )


@pytest.mark.parametrize(
    ("last_active", "recorded"),
    [
        (SINCE - timedelta(seconds=1), True),
        (SINCE, True),
        (SINCE + timedelta(1), False),
    ],
    ids=["older", "at the interval", "recent"],
)
def test_records_activity_once_per_interval(
    store: DjangoSessionStorage,
    user: AbstractBaseUser,
    last_active: datetime,
    recorded: bool,
) -> None:
    original = _make(store, user, updated=EARLIER, last_active=last_active)

    result = store.record_activity(original.id, last_active_at=NOW, since=SINCE)

    persisted = _stored(store, original.id)
    if recorded:
        assert result is not None
        assert result.last_active_at == persisted.last_active_at == NOW
    else:
        assert result is None
        assert persisted.last_active_at == last_active
    assert persisted.updated_at == original.updated_at
    assert persisted.expires_at == original.expires_at


@pytest.mark.parametrize("offset", [-1, 0])
def test_records_only_while_the_session_is_active(
    store: DjangoSessionStorage, user: AbstractBaseUser, offset: int
) -> None:
    original = _aged(store, user, expires_at=NOW + timedelta(microseconds=offset))

    result = store.record_activity(original.id, last_active_at=NOW, since=SINCE)

    persisted = _stored(store, original.id)
    assert (result is not None) is (offset == 0)
    assert persisted.last_active_at == (NOW if offset == 0 else EARLIER)


def test_does_not_record_on_a_revoked_session(
    store: DjangoSessionStorage, user: AbstractBaseUser
) -> None:
    original = _aged(store, user, expires_at=NOW + timedelta(hours=1))
    store.revoke(original.id, revoked_at=EARLIER + timedelta(minutes=1))

    result = store.record_activity(original.id, last_active_at=NOW, since=SINCE)

    assert result is None
    assert _stored(store, original.id).last_active_at == EARLIER


def test_concurrent_uses_record_once(
    store: DjangoSessionStorage, user: AbstractBaseUser
) -> None:
    original = _aged(store, user, expires_at=NOW + timedelta(hours=1))

    first = DjangoSessionStorage().record_activity(
        original.id, last_active_at=NOW, since=SINCE
    )
    # A request that read the session before that write, a moment earlier.
    earlier = NOW - timedelta(seconds=1)
    second = store.record_activity(
        original.id, last_active_at=earlier, since=earlier - timedelta(minutes=5)
    )

    assert first is not None
    assert second is None
    assert _stored(store, original.id).last_active_at == NOW


def test_session_lookup_returns_the_recorded_use(
    store: DjangoSessionStorage, user: AbstractBaseUser
) -> None:
    with time_machine.travel(NOW, tick=False):
        token, _ = create_session(str(user.pk), store, max_age=3600)

    with time_machine.travel(NOW + timedelta(minutes=5), tick=False):
        session = get_session(token, store)

    assert session is not None
    assert session.last_active_at == NOW + timedelta(minutes=5)


@pytest.mark.django_db(transaction=True)
def test_a_database_error_is_logged_and_keeps_the_session(
    store: DjangoSessionStorage,
    user: AbstractBaseUser,
    caplog: pytest.LogCaptureFixture,
) -> None:
    with time_machine.travel(NOW, tick=False):
        token, _ = create_session(str(user.pk), store, max_age=3600)

    def fail_update(execute: Any, sql: str, params: Any, many: bool, context: Any):
        if sql.lstrip().upper().startswith("UPDATE "):
            raise OperationalError("database is locked")
        return execute(sql, params, many, context)

    with (
        time_machine.travel(NOW + timedelta(minutes=5), tick=False),
        caplog.at_level(logging.WARNING, logger="cross_auth.django.storage"),
        connection.execute_wrapper(fail_update),
    ):
        session = get_session(token, store)

    assert session is not None
    assert session.last_active_at == NOW
    assert _stored(store, session.id).last_active_at == NOW
    [record] = caplog.records
    assert record.getMessage() == "Could not record a session's activity"
    assert record.exc_info is not None


def test_revoke_one(store: DjangoSessionStorage, user: AbstractBaseUser) -> None:
    record = _make(store, user)

    assert store.revoke(record.id, revoked_at=NOW) is True

    assert _stored(store, record.id).revoked_at == NOW


def test_revoke_missing_is_noop(store: DjangoSessionStorage) -> None:
    assert store.revoke(uuid.uuid4(), revoked_at=NOW) is False


def test_revoke_leaves_an_expired_session_expired(
    store: DjangoSessionStorage, user: AbstractBaseUser
) -> None:
    record = _make(store, user, expires=NOW - timedelta(days=1))

    assert store.revoke(record.id, revoked_at=NOW) is False

    assert _stored(store, record.id).revoked_at is None
    assert _status(store, record.id) == "expired"


def test_revoke_twice_preserves_original_timestamp(
    store: DjangoSessionStorage, user: AbstractBaseUser
) -> None:
    record = _make(store, user)

    assert store.revoke(record.id, revoked_at=NOW) is True
    assert store.revoke(record.id, revoked_at=NOW + timedelta(hours=1)) is False

    assert _stored(store, record.id).revoked_at == NOW


def test_revoke_all_for_user(
    store: DjangoSessionStorage, user: AbstractBaseUser, other: AbstractBaseUser
) -> None:
    affected = _make(store, user, token_hash="a")
    _make(store, user, token_hash="b")
    _make(store, other, token_hash="c")

    count = store.revoke_all_for_user(str(user.pk), revoked_at=NOW)

    assert count == 2
    assert store.get(token_hash="c", now=NOW) is not None
    assert _stored(store, affected.id).revoked_at is not None


def test_revoke_all_except_one(
    store: DjangoSessionStorage, user: AbstractBaseUser
) -> None:
    keep = _make(store, user, token_hash="a")
    _make(store, user, token_hash="b")

    count = store.revoke_all_for_user(
        str(user.pk), revoked_at=NOW, except_session_id=str(keep.id)
    )

    assert count == 1
    assert _stored(store, keep.id).revoked_at is None


def test_revoke_all_except_an_id_that_matches_nothing_excludes_nothing(
    store: DjangoSessionStorage, user: AbstractBaseUser
) -> None:
    _make(store, user, token_hash="a")

    count = store.revoke_all_for_user(
        str(user.pk), revoked_at=NOW, except_session_id="abc"
    )

    assert count == 1


def test_revoke_all_only_counts_active(
    store: DjangoSessionStorage, user: AbstractBaseUser
) -> None:
    record = _make(store, user, token_hash="a")
    store.revoke(record.id, revoked_at=NOW)

    count = store.revoke_all_for_user(str(user.pk), revoked_at=NOW + timedelta(hours=1))

    assert count == 0


def test_revoke_all_leaves_expired_sessions_expired(
    store: DjangoSessionStorage, user: AbstractBaseUser
) -> None:
    active = _make(store, user, token_hash="a")
    expired = _make(store, user, token_hash="b", expires=NOW - timedelta(days=1))
    # Still active at the exact expiry instant, like session_status.
    at_expiry = _make(store, user, token_hash="c", expires=NOW)

    count = store.revoke_all_for_user(str(user.pk), revoked_at=NOW)

    assert count == 2
    assert _status(store, active.id) == "revoked"
    assert _status(store, at_expiry.id) == "revoked"
    assert _stored(store, expired.id).revoked_at is None


@pytest.mark.parametrize("user_id", ["not-a-user-id", "", None])
def test_a_user_id_that_cannot_be_one_matches_nothing(
    store: DjangoSessionStorage, user: AbstractBaseUser, user_id: object
) -> None:
    _make(store, user)

    assert store.list_for_user(user_id, now=NOW).records == []
    assert store.revoke_all_for_user(user_id, revoked_at=NOW) == 0


def test_list_by_status(store: DjangoSessionStorage, user: AbstractBaseUser) -> None:
    active = _make(store, user, token_hash="a")
    expired = _make(store, user, token_hash="b", expires=NOW - timedelta(days=1))
    revoked = _make(store, user, token_hash="c")
    store.revoke(revoked.id, revoked_at=NOW)

    def listed(status: Any) -> list[uuid.UUID]:
        result = store.list_for_user(str(user.pk), now=NOW, status=status)
        return sorted(record.id for record in result.records)

    assert listed("active") == [active.id]
    assert listed("expired") == [expired.id]
    assert listed("revoked") == [revoked.id]
    assert listed(None) == sorted([active.id, expired.id, revoked.id])


def test_list_only_has_the_users_own_sessions(
    store: DjangoSessionStorage, user: AbstractBaseUser, other: AbstractBaseUser
) -> None:
    own = _make(store, user, token_hash="a")
    _make(store, other, token_hash="b")

    result = store.list_for_user(str(user.pk), now=NOW)

    assert [record.id for record in result.records] == [own.id]
    assert result.next_cursor is None


@pytest.mark.parametrize(
    ("order_by", "expected"),
    [
        ("updated_at_desc", ["a", "b", "c"]),
        ("updated_at_asc", ["c", "b", "a"]),
        ("created_at_desc", ["c", "b", "a"]),
        ("created_at_asc", ["a", "b", "c"]),
        ("expires_at_desc", ["c", "a", "b"]),
        ("expires_at_asc", ["b", "a", "c"]),
    ],
)
def test_list_ordering_supported_values(
    store: DjangoSessionStorage,
    user: AbstractBaseUser,
    order_by: SessionListOrder,
    expected: list[str],
) -> None:
    _make(
        store,
        user,
        token_hash="a",
        created=NOW,
        updated=NOW + timedelta(minutes=2),
        expires=NOW + timedelta(days=20),
    )
    _make(
        store,
        user,
        token_hash="b",
        created=NOW + timedelta(minutes=1),
        updated=NOW + timedelta(minutes=1),
        expires=NOW + timedelta(days=10),
    )
    _make(
        store,
        user,
        token_hash="c",
        created=NOW + timedelta(minutes=2),
        updated=NOW,
        expires=NOW + timedelta(days=30),
    )

    result = store.list_for_user(str(user.pk), now=NOW, order_by=order_by)

    assert _hashes(result.records) == expected


def test_list_rejects_an_unknown_order(
    store: DjangoSessionStorage, user: AbstractBaseUser
) -> None:
    with pytest.raises(ValueError, match="Unsupported order_by"):
        store.list_for_user(
            str(user.pk),
            now=NOW,
            order_by="id_desc",  # ty: ignore[invalid-argument-type]
        )


def test_list_rejects_non_positive_limit(
    store: DjangoSessionStorage, user: AbstractBaseUser
) -> None:
    with pytest.raises(ValueError):
        store.list_for_user(str(user.pk), now=NOW, limit=0)


def test_pagination_with_cursor(
    store: DjangoSessionStorage, user: AbstractBaseUser
) -> None:
    for i in range(5):
        _make(store, user, token_hash=f"t{i}", updated=NOW + timedelta(minutes=i))

    seen: list[str | None] = []
    cursor = None
    for expected in (2, 2, 1):
        page = store.list_for_user(
            str(user.pk), now=NOW, order_by="updated_at_desc", limit=2, cursor=cursor
        )
        assert len(page.records) == expected
        seen += _hashes(page.records)
        cursor = page.next_cursor

    assert seen == ["t4", "t3", "t2", "t1", "t0"]
    assert cursor is None


@pytest.mark.parametrize("order_by", ["updated_at_desc", "updated_at_asc"])
def test_pagination_breaks_ties_with_id(
    store: DjangoSessionStorage, user: AbstractBaseUser, order_by: SessionListOrder
) -> None:
    # All share the same updated_at; only the id tiebreaker separates them.
    ids = [_make(store, user, token_hash=f"t{i}").id for i in range(5)]

    collected: list[uuid.UUID] = []
    cursor = None
    for _ in range(3):
        page = store.list_for_user(
            str(user.pk), now=NOW, order_by=order_by, limit=2, cursor=cursor
        )
        collected.extend(record.id for record in page.records)
        cursor = page.next_cursor
        if cursor is None:
            break

    assert sorted(collected) == sorted(ids)
    assert len(collected) == len(set(collected))  # no duplicates across pages


def test_invalid_cursor_raises(
    store: DjangoSessionStorage, user: AbstractBaseUser
) -> None:
    _make(store, user)

    with pytest.raises(InvalidCursorError):
        store.list_for_user(str(user.pk), now=NOW, cursor="not-a-valid-cursor")


def test_cursor_is_bound_to_its_order_by(
    store: DjangoSessionStorage, user: AbstractBaseUser
) -> None:
    for i in range(3):
        _make(store, user, token_hash=f"t{i}", updated=NOW + timedelta(minutes=i))
    page1 = store.list_for_user(
        str(user.pk), now=NOW, order_by="updated_at_desc", limit=2
    )

    with pytest.raises(InvalidCursorError):
        store.list_for_user(
            str(user.pk), now=NOW, order_by="created_at_asc", cursor=page1.next_cursor
        )


@pytest.mark.parametrize("row_id", ["not-a-uuid", 1, 10**100])
def test_crafted_cursor_without_a_uuid_raises_invalid_cursor(
    store: DjangoSessionStorage, user: AbstractBaseUser, row_id: object
) -> None:
    # Sessions are named by a UUID; another id must not reach the database.
    _make(store, user)
    crafted = base64.urlsafe_b64encode(
        json.dumps(
            {"o": "updated_at_desc", "v": NOW.isoformat(), "id": row_id}
        ).encode()
    ).decode()

    with pytest.raises(InvalidCursorError):
        store.list_for_user(str(user.pk), now=NOW, cursor=crafted)


def test_list_status_filter_at_exact_expiry_boundary(
    store: DjangoSessionStorage, user: AbstractBaseUser
) -> None:
    # Matches cross_auth.session_status: active up to and including expiry, so a
    # session expiring exactly at `now` is active, not expired.
    boundary = _make(store, user, token_hash="boundary", expires=NOW)
    expired = _make(
        store, user, token_hash="expired", expires=NOW - timedelta(seconds=1)
    )

    def listed(status: Any) -> list[uuid.UUID]:
        result = store.list_for_user(str(user.pk), now=NOW, status=status)
        return [record.id for record in result.records]

    assert listed("active") == [boundary.id]
    assert listed("expired") == [expired.id]


def test_login_method_is_stored_and_read_back(
    store: DjangoSessionStorage, user: AbstractBaseUser
) -> None:
    token, created = create_session(str(user.pk), store, login_method="github")

    assert created.login_method == "github"
    session = get_session(token, store)
    assert session is not None
    assert session.login_method == "github"
    (listed,) = store.list_for_user(
        str(user.pk), now=datetime.now(tz=timezone.utc)
    ).records
    assert listed.login_method == "github"


@pytest.mark.django_db(transaction=True)
def test_on_commit_follows_the_outermost_transaction(
    store: DjangoSessionStorage,
) -> None:
    calls: list[str] = []

    store.on_commit(lambda: calls.append("autocommit"))
    assert calls == ["autocommit"]

    with transaction.atomic():
        store.on_commit(lambda: calls.append("outer"))
        assert calls == ["autocommit"]
    assert calls == ["autocommit", "outer"]


# What is Django's own: browser sessions share the table.


@pytest.fixture
def cross_auth_sessions() -> Iterator[None]:
    middleware = [
        "cross_auth.django.sessions.SessionMiddleware"
        if name == "django.contrib.sessions.middleware.SessionMiddleware"
        else name
        for name in settings.MIDDLEWARE
    ]
    with override_settings(
        SESSION_ENGINE="cross_auth.django.sessions", MIDDLEWARE=middleware
    ):
        yield


def _browser_session(user: AbstractBaseUser) -> Session:
    """A signed-in browser session of ``user``, as the session store saves one."""
    browser = SessionStore()
    browser["_auth_user_id"] = str(user.pk)
    browser.save()

    return Session.objects.get(session_key=browser.session_key)


def test_the_storage_leaves_browser_sessions_alone(
    store: DjangoSessionStorage, user: AbstractBaseUser
) -> None:
    browser = _browser_session(user)
    assert browser.user_id == user.pk
    later = NOW + timedelta(days=365)

    assert store.get_any(browser.public_id) is None
    assert store.list_for_user(str(user.pk), now=NOW).records == []
    assert store.refresh(browser.public_id, updated_at=later, expires_at=later) is None
    assert (
        store.record_activity(browser.public_id, last_active_at=later, since=later)
        is None
    )
    assert store.revoke(browser.public_id, revoked_at=NOW) is False
    assert store.revoke_all_for_user(str(user.pk), revoked_at=NOW) == 0
    assert store.clear_expired() == 0

    unchanged = Session.objects.get(session_key=browser.session_key)
    assert unchanged.revoked_at is None
    assert unchanged.expire_date == browser.expire_date
    assert unchanged.last_activity == browser.last_activity


def test_a_browser_session_has_no_token_columns(user: AbstractBaseUser) -> None:
    with time_machine.travel(NOW, tick=False):
        browser = _browser_session(user)

    assert browser.token_hash is None
    assert (browser.client_id, browser.client_name) == (None, None)
    assert browser.revoked_at is None
    assert browser.updated_at == NOW


def test_saving_a_browser_session_moves_its_updated_at(
    user: AbstractBaseUser,
) -> None:
    with time_machine.travel(NOW, tick=False):
        browser = SessionStore()
        browser["cart"] = 1
        browser.save()
    with time_machine.travel(NOW + timedelta(hours=1), tick=False):
        browser["cart"] = 2
        browser.save()

    stored = Session.objects.get(session_key=browser.session_key)
    assert stored.created_at == NOW
    assert stored.updated_at == NOW + timedelta(hours=1)


def test_a_tokens_row_is_an_empty_session_with_a_key_of_its_own(
    store: DjangoSessionStorage,
    user: AbstractBaseUser,
    caplog: pytest.LogCaptureFixture,
) -> None:
    first = _make(store, user, token_hash="a").native
    second = _make(store, user, token_hash="b").native

    assert len(first.session_key) == 32
    assert first.session_key != second.session_key
    # Reading it as session data must not look like tampering to Django.
    with caplog.at_level(logging.WARNING, logger="django.security"):
        assert first.get_decoded() == {}
    assert caplog.records == []


def test_the_session_store_cannot_use_a_tokens_row(
    store: DjangoSessionStorage, user: AbstractBaseUser
) -> None:
    # The key is given to nobody. Even so, sent as a session cookie it must
    # not load, change or delete the token's session.
    record = _make(store, user, expires=datetime.now(timezone.utc) + timedelta(days=1))
    key = record.native.session_key

    browser = SessionStore(session_key=key)
    assert browser.load() == {}
    assert browser.session_key is None

    stale = SessionStore(session_key=key)
    stale["_auth_user_id"] = str(user.pk)
    stale.save()
    assert stale.session_key != key

    SessionStore(session_key=key).delete()
    SessionStore().delete(key)

    kept = _stored(store, record.id).native
    assert kept.session_key == key
    assert kept.get_decoded() == {}
    assert kept.token_hash == "hash"


@pytest.mark.usefixtures("cross_auth_sessions")
def test_a_browser_cannot_take_over_a_tokens_row(
    store: DjangoSessionStorage, user: AbstractBaseUser
) -> None:
    # Through the middleware: a browser that sends the row's key as its
    # session cookie gets a session of its own, in a row of its own.
    record = _make(store, user, expires=datetime.now(timezone.utc) + timedelta(days=1))
    key = record.native.session_key
    client = Client()
    client.cookies[settings.SESSION_COOKIE_NAME] = key

    assert client.get("/").json()["authenticated"] is False
    assert client.post("/remember/", {"value": "mine"}).status_code == 200

    assert client.cookies[settings.SESSION_COOKIE_NAME].value != key
    kept = _stored(store, record.id).native
    assert kept.session_key == key
    assert kept.get_decoded() == {}
    assert Session.objects.filter(token_hash__isnull=True).count() == 1


def test_clear_expired_deletes_expired_tokens_only(
    store: DjangoSessionStorage, user: AbstractBaseUser
) -> None:
    now = datetime.now(timezone.utc)
    active = _make(store, user, token_hash="a", expires=now + timedelta(days=1))
    revoked = _make(store, user, token_hash="b", expires=now + timedelta(days=1))
    store.revoke(revoked.id, revoked_at=now)
    expired = _make(store, user, token_hash="c", expires=now - timedelta(days=1))
    browser = _browser_session(user)
    Session.objects.filter(pk=browser.pk).update(expire_date=now - timedelta(days=1))

    assert store.clear_expired() == 1

    assert store.get_any(expired.id) is None
    # A revoked session keeps its row until it would have expired.
    assert _status(store, revoked.id) == "revoked"
    assert store.get_any(active.id) is not None
    assert Session.objects.filter(pk=browser.pk).exists()


@pytest.mark.usefixtures("cross_auth_sessions")
def test_clearsessions_deletes_expired_tokens_too(
    store: DjangoSessionStorage, user: AbstractBaseUser
) -> None:
    now = datetime.now(timezone.utc)
    active = _make(store, user, token_hash="a", expires=now + timedelta(days=1))
    expired = _make(store, user, token_hash="b", expires=now - timedelta(days=1))

    call_command("clearsessions")

    assert store.get_any(expired.id) is None
    assert store.get_any(active.id) is not None


def test_deleting_the_user_deletes_their_tokens(
    store: DjangoSessionStorage, user: AbstractBaseUser
) -> None:
    record = _make(store, user)

    user.delete()

    assert store.get_any(record.id) is None
