"""A session's last_active_at follows its use, apart from its expiry."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Literal
from unittest import mock

import pytest
import time_machine
from cross_web import HTTPRequest, TestingHTTPRequestAdapter
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from cross_auth._session import (
    SessionConfig,
    create_session,
    get_session,
    resolve_current_session,
)
from cross_auth._storage import AccountsStorage, SecondaryStorage
from cross_auth.fastapi import CrossAuth

from .conftest import BasicMemorySessionStorage, MemorySessionStorage

NOW = datetime(2026, 11, 13, 12, 0, tzinfo=timezone.utc)


def _request(token: str, source: Literal["cookie", "bearer"]) -> HTTPRequest:
    if source == "cookie":
        return HTTPRequest(TestingHTTPRequestAdapter(cookies={"session_id": token}))
    return HTTPRequest(
        TestingHTTPRequestAdapter(headers={"Authorization": f"Bearer {token}"})
    )


@pytest.mark.parametrize("source", ["cookie", "bearer"])
@time_machine.travel(NOW, tick=False)
def test_use_updates_last_active_at_every_five_minutes_by_default(
    session_storage: MemorySessionStorage, source: Literal["cookie", "bearer"]
):
    token, record = create_session("test", session_storage, max_age=3600)
    request = _request(token, source)

    with time_machine.travel(NOW + timedelta(seconds=299), tick=False):
        resolved = resolve_current_session(request, session_storage)
    assert resolved is not None
    assert record.last_active_at == NOW

    with time_machine.travel(NOW + timedelta(seconds=300), tick=False):
        resolved = resolve_current_session(request, session_storage)

    assert resolved is not None
    assert record.last_active_at == NOW + timedelta(seconds=300)
    # Only the activity moved: the expiry stays, so there is no cookie to roll.
    assert resolved.refreshed is False
    assert record.updated_at == NOW
    assert record.expires_at == NOW + timedelta(seconds=3600)


@time_machine.travel(NOW, tick=False)
def test_activity_interval_sets_how_stale_last_active_at_gets(
    session_storage: MemorySessionStorage,
):
    config: SessionConfig = {"activity_interval": 60}
    token, record = create_session("test", session_storage)

    for elapsed, last_active in [(59, 0), (60, 60), (100, 60), (120, 120)]:
        with time_machine.travel(NOW + timedelta(seconds=elapsed), tick=False):
            assert get_session(token, session_storage, config) is not None
        assert record.last_active_at == NOW + timedelta(seconds=last_active)


@time_machine.travel(NOW, tick=False)
def test_activity_interval_zero_records_every_use(
    session_storage: MemorySessionStorage,
):
    config: SessionConfig = {"activity_interval": 0}
    token, record = create_session("test", session_storage)

    for elapsed in (1, 2):
        with time_machine.travel(NOW + timedelta(seconds=elapsed), tick=False):
            get_session(token, session_storage, config)
        assert record.last_active_at == NOW + timedelta(seconds=elapsed)


@time_machine.travel(NOW, tick=False)
def test_activity_interval_none_moves_last_active_at_only_on_refresh(
    session_storage: MemorySessionStorage,
):
    config: SessionConfig = {
        "max_age": 7200,
        "update_age": 3600,
        "activity_interval": None,
    }
    token, record = create_session("test", session_storage, max_age=7200)

    with time_machine.travel(NOW + timedelta(seconds=3599), tick=False):
        get_session(token, session_storage, config)
    assert record.last_active_at == NOW

    with time_machine.travel(NOW + timedelta(seconds=3600), tick=False):
        get_session(token, session_storage, config)
    assert record.last_active_at == NOW + timedelta(seconds=3600)


@time_machine.travel(NOW, tick=False)
def test_sliding_refresh_records_the_use_in_the_same_write(
    session_storage: MemorySessionStorage, monkeypatch
):
    config: SessionConfig = {
        "max_age": 3600,
        "update_age": 600,
        "activity_interval": 60,
    }
    token, record = create_session("test", session_storage, max_age=3600)
    recorded: list[datetime] = []
    original = session_storage.record_activity

    def spy(session_id, *, last_active_at, since):
        recorded.append(last_active_at)
        return original(session_id, last_active_at=last_active_at, since=since)

    monkeypatch.setattr(session_storage, "record_activity", spy)

    with time_machine.travel(NOW + timedelta(seconds=600), tick=False):
        get_session(token, session_storage, config)
    assert record.updated_at == record.last_active_at == NOW + timedelta(seconds=600)
    assert recorded == []

    with time_machine.travel(NOW + timedelta(seconds=660), tick=False):
        get_session(token, session_storage, config)
    assert record.last_active_at == NOW + timedelta(seconds=660)
    assert record.updated_at == NOW + timedelta(seconds=600)
    assert recorded == [NOW + timedelta(seconds=660)]


@time_machine.travel(NOW, tick=False)
def test_logout_lookup_does_not_record_activity(
    session_storage: MemorySessionStorage,
):
    token, record = create_session("test", session_storage)

    with time_machine.travel(NOW + timedelta(hours=1), tick=False):
        resolved = resolve_current_session(
            _request(token, "cookie"), session_storage, refresh=False
        )

    assert resolved is not None
    assert record.last_active_at == NOW


@time_machine.travel(NOW, tick=False)
def test_refused_user_does_not_record_activity(
    session_storage: MemorySessionStorage, accounts_storage: AccountsStorage
):
    token, record = create_session("test", session_storage)

    with time_machine.travel(NOW + timedelta(hours=1), tick=False):
        resolved = resolve_current_session(
            _request(token, "cookie"),
            session_storage,
            accounts_storage=accounts_storage,
            user_can_authenticate=lambda user: False,
        )

    assert resolved is None
    assert record.last_active_at == NOW


@time_machine.travel(NOW, tick=False)
def test_failed_activity_write_keeps_the_session(
    session_storage: MemorySessionStorage, monkeypatch, caplog
):
    token, record = create_session("test", session_storage)

    def fail(session_id, *, last_active_at, since):
        raise RuntimeError("database is read-only")

    monkeypatch.setattr(session_storage, "record_activity", fail)

    with (
        time_machine.travel(NOW + timedelta(hours=1), tick=False),
        caplog.at_level(logging.WARNING, logger="cross_auth._session"),
    ):
        session = get_session(token, session_storage)

    assert session is record
    assert record.last_active_at == NOW
    assert caplog.messages == ["Could not record a session's activity"]


@time_machine.travel(NOW, tick=False)
def test_storage_without_record_activity_keeps_the_previous_behaviour(caplog):
    storage = BasicMemorySessionStorage()
    token, record = create_session("test", storage)

    with (
        time_machine.travel(NOW + timedelta(hours=1), tick=False),
        caplog.at_level(logging.WARNING, logger="cross_auth._session"),
    ):
        assert get_session(token, storage) is record

    assert record.last_active_at == NOW
    assert caplog.messages == []


@time_machine.travel(NOW, tick=False)
def test_lookup_returns_the_session_the_storage_recorded(
    session_storage: MemorySessionStorage, monkeypatch
):
    token, _ = create_session("test", session_storage)
    # A stand-in for the record a storage returns, not the one it was given.
    _, recorded = create_session("test", session_storage)

    def record_activity(session_id, *, last_active_at, since):
        return recorded

    monkeypatch.setattr(session_storage, "record_activity", record_activity)

    with time_machine.travel(NOW + timedelta(hours=1), tick=False):
        assert get_session(token, session_storage) is recorded


def _resolver_app(auth: CrossAuth) -> FastAPI:
    app = FastAPI()

    @app.get("/me")
    def me(user: Any = Depends(auth.get_current_user)) -> dict[str, Any]:
        return {"user": None if user is None else user.id}

    return app


@pytest.mark.parametrize("activity_interval", [300, None])
@time_machine.travel(NOW, tick=False)
def test_custom_user_resolver_records_activity(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: MemorySessionStorage,
    activity_interval: int | None,
):
    auth = CrossAuth(
        providers=[],
        storage=secondary_storage,
        accounts_storage=accounts_storage,
        session_storage=session_storage,
        get_user_from_request=lambda request: accounts_storage.find_user_by_id("test"),
        config={"session": {"activity_interval": activity_interval}},
    )
    token, record = create_session("test", session_storage)
    client = TestClient(_resolver_app(auth))
    client.cookies.set("session_id", token)

    with (
        mock.patch.object(
            session_storage, "get", wraps=session_storage.get
        ) as durable_get,
        time_machine.travel(NOW + timedelta(seconds=300), tick=False),
    ):
        response = client.get("/me")

    assert response.json() == {"user": "test"}
    assert "set-cookie" not in response.headers
    if activity_interval is None:
        # Without sliding or activity, the custom resolver alone runs.
        durable_get.assert_not_called()
        assert record.last_active_at == NOW
    else:
        durable_get.assert_called_once()
        assert record.last_active_at == NOW + timedelta(seconds=300)


@pytest.mark.parametrize("value", [None, 0, 300, 365 * 24 * 60 * 60])
def test_activity_interval_accepts_none_or_up_to_a_year(
    secondary_storage, accounts_storage, session_storage, value
):
    CrossAuth(
        providers=[],
        storage=secondary_storage,
        accounts_storage=accounts_storage,
        session_storage=session_storage,
        config={"session": {"activity_interval": value}},
    )


@pytest.mark.parametrize(
    "value", [-1, 365 * 24 * 60 * 60 + 1, 10**30, True, 1.5, "300"]
)
def test_invalid_activity_interval_is_refused(
    secondary_storage, accounts_storage, session_storage, value
):
    with pytest.raises(ValueError, match=r"\['activity_interval'\] must be None"):
        CrossAuth(
            providers=[],
            storage=secondary_storage,
            accounts_storage=accounts_storage,
            session_storage=session_storage,
            config={"session": {"activity_interval": value}},
        )
