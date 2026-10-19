"""Characterize the shared login-session lifecycle at both entry points.

The browser session callback and the public ``CrossAuth.login`` both run the
``login`` hooks around one session creation and one session cookie. They differ
in where session metadata comes from and in how errors surface: the callback
turns ``CrossAuthException`` into a flow error, ``login`` lets it propagate.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
import respx
from cross_web import Response as CrossWebResponse
from fastapi import FastAPI
from fastapi import Response as FastAPIResponse
from fastapi.testclient import TestClient

from cross_auth._auth_flow import AuthRequest
from cross_auth._session import hash_session_token
from cross_auth.exceptions import CrossAuthException
from cross_auth.fastapi import CrossAuth
from cross_auth.hooks import (
    AfterLoginEvent,
    AfterOAuthCallbackEvent,
    BeforeLoginEvent,
    BeforeOAuthCallbackEvent,
)
from tests.conftest import MemorySessionStorage

from .conftest import mock_token_and_userinfo


def _start_session_flow(secondary_storage, client: TestClient) -> str:
    state = "login-state"
    secondary_storage.set(
        f"oauth:authorization_request:v2:{state}",
        AuthRequest(
            flow="session",
            provider_id="fake",
            state=state,
            browser_binding=hashlib.sha256(b"browser-binding").hexdigest(),
            expires_at=datetime.now(tz=timezone.utc) + timedelta(minutes=10),
            next_url="/dashboard",
        ).model_dump_json(),
    )
    client.cookies.set(f"cross_auth_oauth_{state}", "browser-binding")
    return state


def _session_cookie_headers(values: list[str]) -> list[str]:
    return [value for value in values if value.startswith("session_id=")]


@pytest.fixture
def browser_client(auth: CrossAuth):
    app = FastAPI()
    app.include_router(auth.router)
    with TestClient(app, follow_redirects=False) as client:
        yield client


@respx.mock
def test_browser_login_hooks_wrap_one_session_and_cookie(
    auth: CrossAuth,
    browser_client: TestClient,
    secondary_storage,
    session_storage: MemorySessionStorage,
):
    seen: list[str] = []
    after_events: list[AfterLoginEvent] = []

    @auth.before("oauth.callback")
    def before_callback(event: BeforeOAuthCallbackEvent) -> None:
        seen.append("before:oauth.callback")

    @auth.before("login")
    def before_login(event: BeforeLoginEvent) -> BeforeLoginEvent:
        seen.append("before:login")
        assert session_storage.records == {}
        assert event.response.status_code == 302
        assert event.response.headers == {"Location": "/dashboard"}
        assert not event.response.cookies
        return replace(event, user_id=f"{event.user_id}-mapped")

    @auth.after("login")
    def after_login(event: AfterLoginEvent) -> None:
        seen.append("after:login")
        after_events.append(event)
        event.response.headers = {
            **(event.response.headers or {}),
            "X-Login": event.user_id,
        }

    @auth.after("oauth.callback")
    def after_callback(event: AfterOAuthCallbackEvent) -> None:
        seen.append("after:oauth.callback")

    mock_token_and_userinfo(email="alice@example.com")
    state = _start_session_flow(secondary_storage, browser_client)
    resp = browser_client.get(
        "/fake/callback",
        params={"code": "provider-code", "state": state},
        headers={"User-Agent": "browser-agent/1.0"},
    )

    assert resp.status_code == 302
    assert resp.headers["location"] == "/dashboard"
    assert seen == [
        "before:oauth.callback",
        "before:login",
        "after:login",
        "after:oauth.callback",
    ]

    (record,) = session_storage.records.values()
    (event,) = after_events
    assert record.user_id.endswith("-mapped")
    assert event.user_id == record.user_id
    assert event.session_record is record
    assert record.user_agent == "browser-agent/1.0"
    assert record.client_id is None
    assert record.ip is None
    assert record.token_hash == hash_session_token(event.cookie.value)
    assert resp.headers["x-login"] == record.user_id

    (cookie_header,) = _session_cookie_headers(resp.headers.get_list("set-cookie"))
    assert cookie_header.startswith(f"session_id={event.cookie.value};")


@respx.mock
def test_browser_login_before_hook_can_replace_response(
    auth: CrossAuth,
    browser_client: TestClient,
    secondary_storage,
    session_storage: MemorySessionStorage,
):
    @auth.before("login")
    def replace_response(event: BeforeLoginEvent) -> BeforeLoginEvent:
        return replace(
            event,
            response=CrossWebResponse(
                status_code=303,
                headers={"Location": "/welcome", "X-Replaced": "yes"},
            ),
        )

    mock_token_and_userinfo(email="alice@example.com")
    state = _start_session_flow(secondary_storage, browser_client)
    resp = browser_client.get(
        "/fake/callback", params={"code": "provider-code", "state": state}
    )

    assert resp.status_code == 303
    assert resp.headers["location"] == "/welcome"
    assert resp.headers["x-replaced"] == "yes"
    assert len(session_storage.records) == 1
    assert len(_session_cookie_headers(resp.headers.get_list("set-cookie"))) == 1


@respx.mock
def test_browser_login_veto_becomes_flow_error_without_session(
    auth: CrossAuth,
    browser_client: TestClient,
    secondary_storage,
    session_storage: MemorySessionStorage,
):
    after_called: list[str] = []

    @auth.before("login")
    def veto(event: BeforeLoginEvent) -> None:
        raise CrossAuthException("access_denied", "Login blocked", status_code=403)

    @auth.after("login")
    def after_login(event: AfterLoginEvent) -> None:
        after_called.append("login")

    @auth.after("oauth.callback")
    def after_callback(event: AfterOAuthCallbackEvent) -> None:
        after_called.append("oauth.callback")

    mock_token_and_userinfo(email="alice@example.com")
    state = _start_session_flow(secondary_storage, browser_client)
    resp = browser_client.get(
        "/fake/callback", params={"code": "provider-code", "state": state}
    )

    assert resp.status_code == 403
    assert json.loads(resp.text) == {
        "error": "access_denied",
        "error_description": "Login blocked",
    }
    assert session_storage.records == {}
    assert _session_cookie_headers(resp.headers.get_list("set-cookie")) == []
    assert after_called == []


@respx.mock
def test_browser_login_after_hook_cross_auth_error_is_ignored(
    auth: CrossAuth,
    browser_client: TestClient,
    secondary_storage,
    session_storage: MemorySessionStorage,
):
    @auth.after("login")
    def fail(event: AfterLoginEvent) -> None:
        raise CrossAuthException("server_error", "after hook failed")

    mock_token_and_userinfo(email="alice@example.com")
    state = _start_session_flow(secondary_storage, browser_client)
    resp = browser_client.get(
        "/fake/callback", params={"code": "provider-code", "state": state}
    )

    assert resp.status_code == 302
    assert len(session_storage.records) == 1
    assert len(_session_cookie_headers(resp.headers.get_list("set-cookie"))) == 1


@respx.mock
def test_browser_login_after_hook_failure_propagates_after_session_creation(
    auth: CrossAuth,
    browser_client: TestClient,
    secondary_storage,
    session_storage: MemorySessionStorage,
):
    @auth.after("login")
    def fail(event: AfterLoginEvent) -> None:
        raise RuntimeError("after hook failed")

    mock_token_and_userinfo(email="alice@example.com")
    state = _start_session_flow(secondary_storage, browser_client)
    with pytest.raises(RuntimeError, match="after hook failed"):
        browser_client.get(
            "/fake/callback", params={"code": "provider-code", "state": state}
        )

    assert len(session_storage.records) == 1


def test_public_login_hooks_wrap_one_session_and_cookie(
    auth: CrossAuth,
    session_storage: MemorySessionStorage,
):
    seen: list[str] = []
    after_events: list[AfterLoginEvent] = []

    @auth.before("login")
    def before_login(event: BeforeLoginEvent) -> BeforeLoginEvent:
        seen.append("before:login")
        assert session_storage.records == {}
        assert event.response.status_code == 202
        assert event.response.headers == {
            "content-length": "0",
            "x-existing": "kept",
        }
        assert event.response.cookies == []
        return replace(event, user_id="mapped-user")

    @auth.after("login")
    def after_login(event: AfterLoginEvent) -> None:
        seen.append("after:login")
        after_events.append(event)
        event.response.headers = {
            **(event.response.headers or {}),
            "X-Login": event.user_id,
        }

    response = FastAPIResponse(status_code=202, headers={"X-Existing": "kept"})
    response.set_cookie("other", "cookie")
    result = auth.login(
        "user-1",
        response=response,
        metadata={"user_agent": "cli/2.0", "ip": "203.0.113.7", "client_id": "cli"},
    )

    assert result is None
    assert seen == ["before:login", "after:login"]
    (record,) = session_storage.records.values()
    (event,) = after_events
    assert record.user_id == "mapped-user"
    assert event.user_id == "mapped-user"
    assert event.session_record is record
    assert record.user_agent == "cli/2.0"
    assert record.ip == "203.0.113.7"
    assert record.client_id == "cli"
    assert record.token_hash == hash_session_token(event.cookie.value)

    assert response.status_code == 202
    assert response.headers["x-existing"] == "kept"
    assert response.headers["x-login"] == "mapped-user"
    cookies = response.headers.getlist("set-cookie")
    assert len(cookies) == 2
    assert cookies[0].startswith("other=cookie;")
    assert cookies[1].startswith(f"session_id={event.cookie.value};")


def test_public_login_without_metadata_stores_none(
    auth: CrossAuth,
    session_storage: MemorySessionStorage,
):
    auth.login("user-1", response=FastAPIResponse())

    (record,) = session_storage.records.values()
    assert record.user_agent is None
    assert record.ip is None
    assert record.client_id is None


def test_public_login_veto_propagates_without_session(
    auth: CrossAuth,
    session_storage: MemorySessionStorage,
):
    after_called: list[AfterLoginEvent] = []

    @auth.before("login")
    def veto(event: BeforeLoginEvent) -> None:
        raise CrossAuthException("access_denied", "Login blocked", status_code=403)

    @auth.after("login")
    def after_login(event: AfterLoginEvent) -> None:
        after_called.append(event)

    response = FastAPIResponse()
    with pytest.raises(CrossAuthException) as excinfo:
        auth.login("user-1", response=response)

    assert excinfo.value.error == "access_denied"
    assert session_storage.records == {}
    assert response.headers.getlist("set-cookie") == []
    assert after_called == []


def test_public_login_after_hook_failure_leaves_response_untouched(
    auth: CrossAuth,
    session_storage: MemorySessionStorage,
):
    @auth.after("login")
    def fail(event: AfterLoginEvent) -> None:
        raise RuntimeError("after hook failed")

    response = FastAPIResponse()
    with pytest.raises(RuntimeError, match="after hook failed"):
        auth.login("user-1", response=response)

    # The session row exists, but the hook response is only copied onto the
    # framework response after the after hooks finish.
    assert len(session_storage.records) == 1
    assert response.headers.getlist("set-cookie") == []


def test_public_login_after_hook_cross_auth_error_is_ignored(
    auth: CrossAuth,
    session_storage: MemorySessionStorage,
):
    @auth.after("login")
    def fail(event: AfterLoginEvent) -> None:
        raise CrossAuthException("server_error", "after hook failed")

    response = FastAPIResponse()
    auth.login("user-1", response=response)

    assert len(session_storage.records) == 1
    assert len(_session_cookie_headers(response.headers.getlist("set-cookie"))) == 1
