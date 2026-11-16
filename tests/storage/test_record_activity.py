"""record_activity moves only last_active_at, once per interval, on active rows."""

import logging
import uuid
from datetime import datetime, timedelta, timezone

import pytest
import time_machine
from sqlalchemy import event
from sqlalchemy.exc import OperationalError
from sqlmodel import Session

from cross_auth._session import create_session, get_session

from .models import SessionStore

NOW = datetime(2026, 11, 13, 12, tzinfo=timezone.utc)
SINCE = NOW - timedelta(minutes=5)
EARLIER = NOW - timedelta(hours=1)


@pytest.fixture
def activity_store(signup_engine):
    return SessionStore(session_factory=lambda: Session(signup_engine))


def create(store, *, last_active_at=EARLIER, expires_at=NOW + timedelta(hours=1)):
    return store.create(
        token_hash=uuid.uuid4().hex,
        user_id=uuid.uuid4().hex,
        created_at=EARLIER,
        updated_at=EARLIER,
        expires_at=expires_at,
        last_active_at=last_active_at,
    )


@pytest.mark.parametrize(
    ("last_active_at", "recorded"),
    [
        (None, True),
        (SINCE - timedelta(microseconds=1), True),
        (SINCE, True),
        (SINCE + timedelta(microseconds=1), False),
    ],
    ids=["never", "before-since", "at-since", "after-since"],
)
def test_records_a_use_once_last_active_at_reaches_since(
    activity_store, last_active_at, recorded
):
    original = create(activity_store, last_active_at=last_active_at)

    result = activity_store.record_activity(
        original.id, last_active_at=NOW, since=SINCE
    )

    persisted = activity_store.get_any(original.id)
    if recorded:
        assert result is not None
        assert result.last_active_at == persisted.last_active_at == NOW
    else:
        assert result is None
        assert persisted.last_active_at == last_active_at
    assert persisted.updated_at == original.updated_at
    assert persisted.expires_at == original.expires_at


@pytest.mark.parametrize("offset", [-1, 0])
def test_records_only_while_the_session_is_active(activity_store, offset):
    original = create(activity_store, expires_at=NOW + timedelta(microseconds=offset))

    result = activity_store.record_activity(
        original.id, last_active_at=NOW, since=SINCE
    )

    persisted = activity_store.get_any(original.id)
    assert (result is not None) is (offset == 0)
    assert persisted.last_active_at == (NOW if offset == 0 else EARLIER)


def test_does_not_record_on_a_revoked_session(activity_store):
    original = create(activity_store)
    activity_store.revoke(original.id, revoked_at=EARLIER + timedelta(minutes=1))

    result = activity_store.record_activity(
        original.id, last_active_at=NOW, since=SINCE
    )

    assert result is None
    assert activity_store.get_any(original.id).last_active_at == EARLIER


def test_concurrent_uses_record_once(activity_store, signup_engine):
    original = create(activity_store)
    other_request = SessionStore(session_factory=lambda: Session(signup_engine))

    first = other_request.record_activity(original.id, last_active_at=NOW, since=SINCE)
    # A request that read the session before that write, a moment earlier.
    earlier = NOW - timedelta(seconds=1)
    second = activity_store.record_activity(
        original.id, last_active_at=earlier, since=earlier - timedelta(minutes=5)
    )

    assert first is not None
    assert second is None
    assert activity_store.get_any(original.id).last_active_at == NOW


@pytest.mark.parametrize("session_id", [99999, "not-an-id"])
def test_unknown_session_records_nothing(activity_store, session_id):
    assert (
        activity_store.record_activity(session_id, last_active_at=NOW, since=SINCE)
        is None
    )


def test_delayed_refresh_keeps_a_later_recorded_use(activity_store, signup_engine):
    original = create(activity_store)
    other_request = SessionStore(session_factory=lambda: Session(signup_engine))

    # Another request records a use after this one read the session, and
    # commits before this one's refresh, which carries an earlier time.
    assert other_request.record_activity(
        original.id, last_active_at=NOW + timedelta(seconds=3), since=SINCE
    )
    refreshed = activity_store.refresh(
        original.id,
        updated_at=NOW + timedelta(seconds=2),
        expires_at=NOW + timedelta(days=1),
        last_active_at=NOW + timedelta(seconds=2),
    )

    persisted = activity_store.get_any(original.id)
    assert refreshed is not None
    assert refreshed.updated_at == persisted.updated_at == NOW + timedelta(seconds=2)
    assert refreshed.expires_at == persisted.expires_at == NOW + timedelta(days=1)
    assert (
        refreshed.last_active_at
        == persisted.last_active_at
        == NOW + timedelta(seconds=3)
    )


def test_session_lookup_returns_the_recorded_use(activity_store):
    with time_machine.travel(NOW, tick=False):
        token, _ = create_session("u1", activity_store, max_age=3600)

    with time_machine.travel(NOW + timedelta(minutes=5), tick=False):
        session = get_session(token, activity_store)

    assert session is not None
    assert session.last_active_at == NOW + timedelta(minutes=5)


def test_a_database_error_is_logged_and_keeps_the_session(
    activity_store, signup_engine, caplog
):
    with time_machine.travel(NOW, tick=False):
        token, _ = create_session("u1", activity_store, max_age=3600)

    def fail_update(connection, cursor, statement, parameters, context, executemany):
        if statement.startswith("UPDATE usersession"):
            raise OperationalError(
                statement, parameters, Exception("database is locked")
            )

    event.listen(signup_engine, "before_cursor_execute", fail_update)
    try:
        with (
            time_machine.travel(NOW + timedelta(minutes=5), tick=False),
            caplog.at_level(logging.WARNING, logger="cross_auth.storage.sqlmodel"),
        ):
            session = get_session(token, activity_store)
    finally:
        event.remove(signup_engine, "before_cursor_execute", fail_update)

    assert session is not None
    assert session.last_active_at == NOW
    assert activity_store.get_any(session.id).last_active_at == NOW
    [record] = caplog.records
    assert record.getMessage() == "Could not record a session's activity"
    assert record.exc_info is not None


def test_a_failed_connection_is_logged_and_records_nothing(activity_store, caplog):
    original = create(activity_store)

    def connect():
        # A factory such as Session(engine.connect()) connects as it is called.
        raise OperationalError("connect", {}, Exception("connection refused"))

    unreachable = SessionStore(session_factory=connect)
    with caplog.at_level(logging.WARNING, logger="cross_auth.storage.sqlmodel"):
        result = unreachable.record_activity(
            original.id, last_active_at=NOW, since=SINCE
        )

    assert result is None
    assert activity_store.get_any(original.id).last_active_at == EARLIER
    assert caplog.messages == ["Could not record a session's activity"]
