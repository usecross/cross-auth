"""One ``login`` lifecycle across every way Cross Auth logs someone in.

Browser session callbacks and ``CrossAuth.login`` issue a cookie;
``issue_session_token`` and the ``/token`` grants issue a bearer credential,
either a Cross Auth session or one minted by an application ``token_issuer``.
Each runs exactly one ``before("login")``/``after("login")`` pair around at most
one session. Identity verification, account connection/linking, and sliding
refresh are not logins.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Any, get_args
from urllib.parse import parse_qs, urlparse

import pytest
import respx
import time_machine
from cross_web import Response as CrossWebResponse
from fastapi import Depends, FastAPI
from fastapi import Response as FastAPIResponse
from fastapi.testclient import TestClient

from cross_auth._auth_flow import AuthRequest
from cross_auth._session import hash_session_token
from cross_auth._tokens import TokenIssueRequest
from cross_auth.exceptions import CrossAuthException
from cross_auth.fastapi import CrossAuth, SessionCookieMiddleware
from cross_auth.hooks import AfterLoginEvent, BeforeLoginEvent
from cross_auth.hooks._types import HookEventName
from tests.conftest import TEST_PASSWORD, MemorySessionStorage

from .conftest import (
    LEGACY_APP_OAUTH_SERVER,
    mock_token_and_userinfo,
    start_provider_auth,
)
from ..conftest import legacy_password_grant

NOW = datetime(2026, 10, 19, 12, 0, tzinfo=timezone.utc)
# S256 challenge for the code verifier "test".
_CODE_CHALLENGE = "n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg"
_CODE_VERIFIER = "test"


def _trace_hooks(auth: CrossAuth) -> list[str]:
    trace: list[str] = []
    hooks = auth._context.hooks
    for name in get_args(HookEventName):
        hooks.register_before(
            name, lambda event, name=name: trace.append(f"before:{name}")
        )
        hooks.register_after(
            name, lambda event, name=name: trace.append(f"after:{name}")
        )
    return trace


def _capture_login(
    auth: CrossAuth,
) -> tuple[list[BeforeLoginEvent], list[AfterLoginEvent]]:
    before: list[BeforeLoginEvent] = []
    after: list[AfterLoginEvent] = []
    auth.before("login")(before.append)
    auth.after("login")(after.append)
    return before, after


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


def _browser_callback(secondary_storage, client: TestClient, **kwargs: Any):
    mock_token_and_userinfo(email="alice@example.com")
    state = _start_session_flow(secondary_storage, client)
    return client.get(
        "/fake/callback",
        params={"code": "provider-code", "state": state},
        **kwargs,
    )


def _session_cookie_headers(values: list[str]) -> list[str]:
    return [value for value in values if value.startswith("session_id=")]


def _cookie_value(header: str) -> str:
    return header.split(";", 1)[0].split("=", 1)[1]


def _client(auth: CrossAuth) -> TestClient:
    app = FastAPI()
    app.include_router(auth.router)
    return TestClient(app, follow_redirects=False)


@pytest.fixture
def browser_client(auth: CrossAuth):
    with _client(auth) as client:
        yield client


def _password_grant(client: TestClient, **data: str):
    with legacy_password_grant():
        return client.post(
            "/token",
            data={
                "grant_type": "password",
                "client_id": "app-client",
                "username": "test@example.com",
                "password": TEST_PASSWORD,
                **data,
            },
            headers={"User-Agent": "cli/3.0"},
        )


# --- Browser cookie login -------------------------------------------------


@respx.mock
def test_browser_login_runs_one_lifecycle_around_one_session_and_cookie(
    auth: CrossAuth,
    browser_client: TestClient,
    secondary_storage,
    session_storage: MemorySessionStorage,
):
    trace = _trace_hooks(auth)
    before, after = _capture_login(auth)

    resp = _browser_callback(
        secondary_storage, browser_client, headers={"User-Agent": "browser/1.0"}
    )

    assert resp.status_code == 302
    assert resp.headers["location"] == "/dashboard"
    assert trace == [
        "before:oauth.callback",
        "before:user.create",
        "before:social_account.create",
        "after:user.create",
        "after:social_account.create",
        "before:login",
        "after:login",
        "after:oauth.callback",
    ]

    (record,) = session_storage.records.values()
    (before_event,) = before
    (after_event,) = after
    assert before_event.credential == "cookie"
    assert before_event.max_age == 86400
    assert before_event.metadata == {
        "user_agent": "browser/1.0",
        "login_method": "fake",
    }
    assert after_event.user_id == record.user_id == before_event.user_id
    assert after_event.credential == "cookie"
    assert after_event.session_record is record
    assert after_event.response is not None

    (cookie_header,) = _session_cookie_headers(resp.headers.get_list("set-cookie"))
    assert record.token_hash == hash_session_token(_cookie_value(cookie_header))
    assert record.user_agent == "browser/1.0"


@respx.mock
def test_browser_login_hooks_adjust_response_and_lifetime(
    auth: CrossAuth,
    browser_client: TestClient,
    secondary_storage,
    session_storage: MemorySessionStorage,
):
    @auth.before("login")
    def shorten_and_redirect(event: BeforeLoginEvent) -> BeforeLoginEvent:
        assert event.response is not None
        assert event.response.headers == {"Location": "/dashboard"}
        assert not event.response.cookies
        return replace(
            event,
            max_age=600,
            response=CrossWebResponse(
                status_code=303, headers={"Location": "/welcome"}
            ),
        )

    @auth.after("login")
    def add_header(event: AfterLoginEvent) -> None:
        assert event.response is not None
        event.response.headers = {
            **(event.response.headers or {}),
            "X-Login": event.user_id,
        }

    with time_machine.travel(NOW, tick=False):
        resp = _browser_callback(secondary_storage, browser_client)

    assert resp.status_code == 303
    assert resp.headers["location"] == "/welcome"
    (record,) = session_storage.records.values()
    assert resp.headers["x-login"] == record.user_id
    assert record.expires_at == NOW + timedelta(seconds=600)
    (cookie_header,) = _session_cookie_headers(resp.headers.get_list("set-cookie"))
    assert "Max-Age=600" in cookie_header


@respx.mock
def test_browser_login_veto_becomes_flow_error_without_session(
    auth: CrossAuth,
    browser_client: TestClient,
    secondary_storage,
    session_storage: MemorySessionStorage,
):
    @auth.before("login")
    def veto(event: BeforeLoginEvent) -> None:
        raise CrossAuthException("access_denied", "Login blocked", status_code=403)

    trace = _trace_hooks(auth)
    resp = _browser_callback(secondary_storage, browser_client)

    assert resp.status_code == 403
    assert json.loads(resp.text) == {
        "error": "access_denied",
        "error_description": "Login blocked",
    }
    assert session_storage.records == {}
    assert _session_cookie_headers(resp.headers.get_list("set-cookie")) == []
    assert "after:login" not in trace
    assert "after:oauth.callback" not in trace


@respx.mock
def test_browser_login_rejects_user_id_rewrite(
    auth: CrossAuth,
    browser_client: TestClient,
    secondary_storage,
    session_storage: MemorySessionStorage,
):
    @auth.before("login")
    def impersonate(event: BeforeLoginEvent) -> BeforeLoginEvent:
        return replace(event, user_id="test")

    trace = _trace_hooks(auth)
    with pytest.raises(ValueError, match="cannot change user_id"):
        _browser_callback(secondary_storage, browser_client)

    assert session_storage.records == {}
    assert "after:login" not in trace


@respx.mock
def test_browser_login_after_hook_auth_error_surfaces_after_session_is_saved(
    auth: CrossAuth,
    browser_client: TestClient,
    secondary_storage,
    session_storage: MemorySessionStorage,
):
    @auth.after("login")
    def fail(event: AfterLoginEvent) -> None:
        raise CrossAuthException("server_error", "after hook failed", status_code=500)

    trace = _trace_hooks(auth)
    resp = _browser_callback(secondary_storage, browser_client)

    # The structured error reaches the client like any other flow error. The
    # committed session is not undone, but its cookie is not delivered.
    assert resp.status_code == 500
    assert resp.json()["error_description"] == "after hook failed"
    assert len(session_storage.records) == 1
    assert _session_cookie_headers(resp.headers.get_list("set-cookie")) == []
    assert "after:oauth.callback" not in trace


@respx.mock
def test_browser_login_after_hook_failure_propagates_after_session_is_saved(
    auth: CrossAuth,
    browser_client: TestClient,
    secondary_storage,
    session_storage: MemorySessionStorage,
):
    @auth.after("login")
    def fail(event: AfterLoginEvent) -> None:
        raise RuntimeError("after hook failed")

    with pytest.raises(RuntimeError, match="after hook failed"):
        _browser_callback(secondary_storage, browser_client)

    assert len(session_storage.records) == 1


# --- CrossAuth.login --------------------------------------------------------


def test_public_login_runs_one_lifecycle_around_one_session_and_cookie(
    auth: CrossAuth,
    session_storage: MemorySessionStorage,
):
    trace = _trace_hooks(auth)
    before, after = _capture_login(auth)

    @auth.after("login")
    def add_header(event: AfterLoginEvent) -> None:
        assert event.response is not None
        event.response.headers = {**(event.response.headers or {}), "X-Login": "1"}

    response = FastAPIResponse(status_code=202, headers={"X-Existing": "kept"})
    response.set_cookie("other", "cookie")
    result = auth.login(
        "test",
        response=response,
        metadata={"user_agent": "cli/2.0", "ip": "203.0.113.7", "client_id": "cli"},
    )

    assert result is None
    assert trace == ["before:login", "after:login"]
    (record,) = session_storage.records.values()
    (before_event,) = before
    (after_event,) = after
    assert before_event.credential == "cookie"
    assert after_event.user_id == record.user_id == "test"
    assert after_event.session_record is record
    assert (record.user_agent, record.ip, record.client_id) == (
        "cli/2.0",
        "203.0.113.7",
        "cli",
    )

    assert response.status_code == 202
    assert response.headers["x-existing"] == "kept"
    assert response.headers["x-login"] == "1"
    cookies = response.headers.getlist("set-cookie")
    assert len(cookies) == 2
    assert cookies[0].startswith("other=cookie;")
    assert record.token_hash == hash_session_token(_cookie_value(cookies[1]))


def test_public_login_veto_and_rewrite_create_no_session(
    auth: CrossAuth,
    session_storage: MemorySessionStorage,
):
    @auth.before("login")
    def policy(event: BeforeLoginEvent) -> BeforeLoginEvent:
        if event.user_id == "suspended":
            raise CrossAuthException("access_denied", "Login blocked", status_code=403)
        return replace(event, user_id="admin")

    trace = _trace_hooks(auth)
    response = FastAPIResponse()
    with pytest.raises(CrossAuthException) as excinfo:
        auth.login("suspended", response=response)
    assert excinfo.value.error == "access_denied"

    with pytest.raises(ValueError, match="cannot change user_id"):
        auth.login("test", response=response)

    assert session_storage.records == {}
    assert response.headers.getlist("set-cookie") == []
    assert "after:login" not in trace


@pytest.mark.parametrize(
    "error",
    [RuntimeError("after hook failed"), CrossAuthException("server_error")],
)
def test_public_login_after_hook_failure_propagates_after_session_is_saved(
    auth: CrossAuth,
    session_storage: MemorySessionStorage,
    error: Exception,
):
    @auth.after("login")
    def fail(event: AfterLoginEvent) -> None:
        raise error

    response = FastAPIResponse()
    with pytest.raises(type(error)):
        auth.login("test", response=response)

    # The session row exists, but the hook response is only copied onto the
    # framework response after the after hooks finish.
    assert len(session_storage.records) == 1
    assert response.headers.getlist("set-cookie") == []


# --- issue_session_token ---------------------------------------------------


@time_machine.travel(NOW, tick=False)
def test_issue_session_token_runs_login_lifecycle_without_response(
    auth: CrossAuth,
    session_storage: MemorySessionStorage,
):
    trace = _trace_hooks(auth)
    before, after = _capture_login(auth)

    @auth.before("login")
    def clamp(event: BeforeLoginEvent) -> BeforeLoginEvent:
        assert event.max_age is not None
        return replace(
            event,
            max_age=min(event.max_age, 3600),
            metadata={**(event.metadata or {}), "client_name": "ios"},
        )

    token, record = auth.issue_session_token(
        "test", max_age=86400, metadata={"user_agent": "ios/17"}
    )

    assert trace == ["before:login", "after:login"]
    (before_event,) = before
    (after_event,) = after
    assert before_event.credential == "bearer"
    assert before_event.response is None
    assert before_event.max_age == 86400
    assert after_event.credential == "bearer"
    assert after_event.response is None
    assert after_event.session_record is record
    (stored,) = session_storage.records.values()
    assert stored is record
    assert stored.token_hash == hash_session_token(token)
    assert record.expires_at == NOW + timedelta(seconds=3600)
    assert (record.user_agent, record.client_name) == ("ios/17", "ios")


def test_issue_session_token_veto_and_invalid_rewrites_create_no_session(
    auth: CrossAuth,
    session_storage: MemorySessionStorage,
):
    rewrites = {
        "suspended": None,
        "rewrite": {"user_id": "admin"},
        "credential": {"credential": "cookie"},
        "response": {"response": CrossWebResponse(status_code=200)},
    }

    @auth.before("login")
    def policy(event: BeforeLoginEvent) -> BeforeLoginEvent:
        changes = rewrites[event.user_id]
        if changes is None:
            raise CrossAuthException("access_denied")
        return replace(event, **changes)

    trace = _trace_hooks(auth)
    with pytest.raises(CrossAuthException):
        auth.issue_session_token("suspended")
    for user_id in ("rewrite", "credential", "response"):
        with pytest.raises(ValueError, match="login before hooks cannot"):
            auth.issue_session_token(user_id)

    assert session_storage.records == {}
    assert "after:login" not in trace


def test_issue_session_token_after_hook_failure_leaves_session(
    auth: CrossAuth,
    session_storage: MemorySessionStorage,
):
    @auth.after("login")
    def fail(event: AfterLoginEvent) -> None:
        raise CrossAuthException("server_error")

    with pytest.raises(CrossAuthException):
        auth.issue_session_token("test")

    assert len(session_storage.records) == 1


# --- /token -----------------------------------------------------------------


@time_machine.travel(NOW, tick=False)
def test_password_grant_runs_one_login_lifecycle(
    build_auth,
    session_storage: MemorySessionStorage,
):
    auth = build_auth(oauth_server=LEGACY_APP_OAUTH_SERVER)
    trace = _trace_hooks(auth)
    before, after = _capture_login(auth)

    @auth.before("login")
    def clamp(event: BeforeLoginEvent) -> BeforeLoginEvent:
        return replace(event, max_age=120)

    with _client(auth) as client:
        resp = _password_grant(client)

    assert resp.status_code == 200
    assert trace == [
        "before:token.password",
        "before:login",
        "after:login",
        "after:token.password",
    ]
    (record,) = session_storage.records.values()
    (before_event,) = before
    (after_event,) = after
    assert before_event.credential == "bearer"
    assert before_event.metadata == {
        "client_id": "app-client",
        "user_agent": "cli/3.0",
        "login_method": "password",
    }
    assert after_event.session_record is record
    assert record.user_id == "test"
    assert record.token_hash == hash_session_token(resp.json()["access_token"])
    assert record.expires_at == NOW + timedelta(seconds=120)
    assert resp.json()["expires_in"] == 120


def test_failed_password_grant_runs_no_login(
    build_auth,
    session_storage: MemorySessionStorage,
):
    auth = build_auth(oauth_server=LEGACY_APP_OAUTH_SERVER)
    trace = _trace_hooks(auth)

    with _client(auth) as client:
        resp = _password_grant(client, password="wrong")

    assert resp.status_code == 400
    assert trace == ["before:token.password"]
    assert session_storage.records == {}


def test_password_grant_login_veto_is_a_token_error(
    build_auth,
    session_storage: MemorySessionStorage,
):
    auth = build_auth(oauth_server=LEGACY_APP_OAUTH_SERVER)
    trace = _trace_hooks(auth)

    @auth.before("login")
    def veto(event: BeforeLoginEvent) -> None:
        raise CrossAuthException("access_denied", "Login blocked")

    with _client(auth) as client:
        resp = _password_grant(client)

    assert resp.status_code == 400
    assert resp.json() == {
        "error": "access_denied",
        "error_description": "Login blocked",
    }
    assert session_storage.records == {}
    assert trace == ["before:token.password", "before:login"]


@respx.mock
def test_authorization_code_login_happens_once_at_redemption(
    auth: CrossAuth,
    session_storage: MemorySessionStorage,
):
    mock_token_and_userinfo(email="bob@example.com", provider_user_id="bob-1")
    trace = _trace_hooks(auth)
    _, after = _capture_login(auth)

    with _client(auth) as client:
        _, state = start_provider_auth(
            client,
            "/fake/authorize",
            params={
                "client_id": "app-client",
                "redirect_uri": "http://client.example/cb",
                "response_type": "code",
                "code_challenge": _CODE_CHALLENGE,
                "code_challenge_method": "S256",
            },
        )
        callback = client.get(
            "/fake/callback", params={"code": "provider-code", "state": state}
        )
        code = parse_qs(urlparse(callback.headers["location"]).query)["code"][0]

        # Minting the authorization code verifies identity; it is not a login.
        assert "before:login" not in trace
        assert session_storage.records == {}

        trace.clear()
        resp = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": "app-client",
                "code": code,
                "redirect_uri": "http://client.example/cb",
                "code_verifier": _CODE_VERIFIER,
            },
        )

    assert resp.status_code == 200
    assert trace == [
        "before:token.authorization_code",
        "before:login",
        "after:login",
        "after:token.authorization_code",
    ]
    (record,) = session_storage.records.values()
    (after_event,) = after
    assert after_event.session_record is record
    assert after_event.user_id == record.user_id
    assert record.client_id == "app-client"
    assert record.token_hash == hash_session_token(resp.json()["access_token"])


def test_token_after_hook_failures_surface_after_session_is_saved(
    build_auth,
    session_storage: MemorySessionStorage,
):
    auth = build_auth(oauth_server=LEGACY_APP_OAUTH_SERVER)

    @auth.after("token.password")
    def fail(event: Any) -> None:
        raise CrossAuthException("server_error", "after hook failed")

    with _client(auth) as client, pytest.raises(CrossAuthException):
        _password_grant(client)

    assert len(session_storage.records) == 1


# --- Application token_issuer ----------------------------------------------


@pytest.fixture
def issued() -> list[TokenIssueRequest]:
    return []


@pytest.fixture
def issuer_auth(build_auth, issued: list[TokenIssueRequest]) -> CrossAuth:
    def token_issuer(request: TokenIssueRequest) -> tuple[str, int]:
        issued.append(request)
        return f"jwt-for-{request.user_id}", 900

    return build_auth(
        oauth_server=replace(LEGACY_APP_OAUTH_SERVER, token_issuer=token_issuer)
    )


def test_token_issuer_credentials_are_logins_without_sessions(
    issuer_auth: CrossAuth,
    session_storage: MemorySessionStorage,
    issued: list[TokenIssueRequest],
):
    trace = _trace_hooks(issuer_auth)
    before, after = _capture_login(issuer_auth)

    with _client(issuer_auth) as client:
        resp = _password_grant(client)

    assert resp.status_code == 200
    assert resp.json()["access_token"] == "jwt-for-test"
    assert resp.json()["expires_in"] == 900
    assert trace == [
        "before:token.password",
        "before:login",
        "after:login",
        "after:token.password",
    ]
    (before_event,) = before
    (after_event,) = after
    assert (before_event.credential, before_event.max_age, before_event.metadata) == (
        "bearer",
        None,
        None,
    )
    assert after_event.user_id == "test"
    assert after_event.session_record is None
    assert len(issued) == 1
    assert session_storage.records == {}


@pytest.mark.parametrize(
    ("changes", "match"),
    [
        ({"user_id": "admin"}, "cannot change user_id"),
        ({"max_age": 60}, "token_issuer"),
        ({"metadata": {"client_name": "x"}}, "token_issuer"),
    ],
)
def test_token_issuer_rejects_rewrites_without_minting(
    issuer_auth: CrossAuth,
    issued: list[TokenIssueRequest],
    changes: dict[str, Any],
    match: str,
):
    @issuer_auth.before("login")
    def rewrite(event: BeforeLoginEvent) -> BeforeLoginEvent:
        return replace(event, **changes)

    trace = _trace_hooks(issuer_auth)
    with _client(issuer_auth) as client, pytest.raises(ValueError, match=match):
        _password_grant(client)

    assert issued == []
    assert "after:login" not in trace


def test_token_issuer_veto_mints_nothing(
    issuer_auth: CrossAuth,
    issued: list[TokenIssueRequest],
):
    @issuer_auth.before("login")
    def veto(event: BeforeLoginEvent) -> None:
        raise CrossAuthException("access_denied")

    trace = _trace_hooks(issuer_auth)
    with _client(issuer_auth) as client:
        resp = _password_grant(client)

    assert resp.status_code == 400
    assert resp.json()["error"] == "access_denied"
    assert issued == []
    assert "after:login" not in trace


def test_token_issuer_after_hook_failure_surfaces_after_minting(
    issuer_auth: CrossAuth,
    issued: list[TokenIssueRequest],
):
    @issuer_auth.after("login")
    def fail(event: AfterLoginEvent) -> None:
        raise RuntimeError("audit unavailable")

    with _client(issuer_auth) as client, pytest.raises(RuntimeError):
        _password_grant(client)

    assert len(issued) == 1


# --- Not logins -------------------------------------------------------------


@respx.mock
def test_connect_is_not_a_login(
    auth: CrossAuth,
    browser_client: TestClient,
    session_storage: MemorySessionStorage,
):
    mock_token_and_userinfo(email="demo@example.com", provider_user_id="fake-123")
    trace = _trace_hooks(auth)

    start = browser_client.get(
        "/fake/connect", headers={"Authorization": "Bearer test"}
    )
    state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]
    callback = browser_client.get(
        "/fake/callback",
        params={"code": "provider-code", "state": state},
        headers={"Authorization": "Bearer test"},
    )

    assert callback.status_code == 302
    assert "before:social_account.create" in trace
    assert not any(name.endswith(":login") for name in trace)
    assert session_storage.records == {}


@respx.mock
def test_link_and_finalize_link_are_not_logins(
    build_auth,
    session_storage: MemorySessionStorage,
):
    mock_token_and_userinfo(email="test@example.com", provider_user_id="linked-id")
    auth = build_auth(
        config={
            "account_linking": {"enabled": True},
            "session": {"cookies": {"auth": True}},
        }
    )
    trace = _trace_hooks(auth)

    with _client(auth) as client:
        start = client.post(
            "/fake/link",
            headers={"Authorization": "Bearer test"},
            json={
                "redirect_uri": "http://client.example/cb",
                "code_challenge": _CODE_CHALLENGE,
                "code_challenge_method": "S256",
                "client_id": "app-client",
            },
        )
        state = parse_qs(urlparse(start.json()["authorization_url"]).query)["state"][0]
        callback = client.get(
            "/fake/callback", params={"code": "provider-code", "state": state}
        )
        link_code = parse_qs(urlparse(callback.headers["location"]).query)["link_code"][
            0
        ]
        finalize = client.post(
            "/fake/finalize-link",
            headers={"Authorization": "Bearer test"},
            json={"link_code": link_code, "code_verifier": _CODE_VERIFIER},
        )

    assert finalize.status_code == 200
    assert "after:oauth.finalize_link" in trace
    assert not any(name.endswith(":login") for name in trace)
    assert session_storage.records == {}


def test_sliding_refresh_is_not_a_login(
    build_auth,
    session_storage: MemorySessionStorage,
):
    auth = build_auth(
        config={
            "session": {
                "max_age": 60,
                "update_age": 10,
                "cookies": {"auth": True, "secure": False},
            }
        }
    )
    app = FastAPI()
    app.add_middleware(SessionCookieMiddleware)

    @app.get("/me")
    def me(session: Any = Depends(auth.get_current_session)) -> dict[str, Any]:
        return {"user": None if session is None else session.user_id}

    with time_machine.travel(NOW, tick=False) as clock:
        token, record = auth.issue_session_token("test")
        trace = _trace_hooks(auth)
        clock.shift(timedelta(seconds=20))
        with TestClient(app) as client:
            client.cookies.set("session_id", token)
            resp = client.get("/me")

    assert resp.json() == {"user": "test"}
    assert "session_id=" in resp.headers["set-cookie"]
    assert record.expires_at == NOW + timedelta(seconds=80)
    assert trace == []
    assert len(session_storage.records) == 1
