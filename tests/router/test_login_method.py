"""``login_method``: how a login signed in.

Every ``login`` event carries it: the provider id, ``"password"`` for the
password grant, or what the application passed. Before hooks may replace it,
and the approved value is what the session or the ``token_issuer`` gets. The
authorization code carries the provider from the callback to ``/token``.
"""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

import pytest
import respx
from fastapi import FastAPI
from fastapi import Response as FastAPIResponse
from fastapi.testclient import TestClient

from cross_auth._issuer import AuthorizationCodeGrantData
from cross_auth._storage import SecondaryStorage
from cross_auth._tokens import TokenIssueRequest
from cross_auth.exceptions import CrossAuthException
from cross_auth.fastapi import CrossAuth
from cross_auth.hooks import AfterLoginEvent, BeforeLoginEvent
from tests.conftest import TEST_PASSWORD, MemorySessionStorage

from ..conftest import legacy_password_grant
from .conftest import (
    LEGACY_APP_OAUTH_SERVER,
    mock_token_and_userinfo,
    start_provider_auth,
)

# S256 challenge for the code verifier "test".
_CODE_CHALLENGE = "n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg"
_CODE_VERIFIER = "test"
_REDIRECT_URI = "http://client.example/cb"


def _client(auth: CrossAuth) -> TestClient:
    app = FastAPI()
    app.include_router(auth.router)
    return TestClient(app, follow_redirects=False)


def _browser_login(client: TestClient):
    mock_token_and_userinfo(email="alice@example.com")
    _, state = start_provider_auth(client, "/fake/login")
    return client.get(
        "/fake/callback", params={"code": "provider-code", "state": state}
    )


def _authorization_code(client: TestClient) -> str:
    mock_token_and_userinfo(email="bob@example.com", provider_user_id="bob-1")
    _, state = start_provider_auth(
        client,
        "/fake/authorize",
        params={
            "client_id": "app-client",
            "redirect_uri": _REDIRECT_URI,
            "response_type": "code",
            "code_challenge": _CODE_CHALLENGE,
            "code_challenge_method": "S256",
        },
    )
    callback = client.get(
        "/fake/callback", params={"code": "provider-code", "state": state}
    )
    return parse_qs(urlparse(callback.headers["location"]).query)["code"][0]


def _redeem(client: TestClient, code: str):
    return client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "client_id": "app-client",
            "code": code,
            "redirect_uri": _REDIRECT_URI,
            "code_verifier": _CODE_VERIFIER,
        },
    )


def _password_grant(client: TestClient):
    with legacy_password_grant():
        return client.post(
            "/token",
            data={
                "grant_type": "password",
                "client_id": "app-client",
                "username": "test@example.com",
                "password": TEST_PASSWORD,
            },
        )


def _store_code_without_login_method(secondary_storage: SecondaryStorage) -> str:
    """Store an authorization code the way a version without the field did."""
    data = AuthorizationCodeGrantData(
        user_id="test",
        # Long enough that a slow run can't expire it before the test redeems it.
        expires_at=datetime.now(tz=timezone.utc) + timedelta(minutes=10),
        client_id="app-client",
        redirect_uri=_REDIRECT_URI,
        code_challenge=_CODE_CHALLENGE,
        code_challenge_method="S256",
    ).model_dump(mode="json")
    del data["login_method"]
    secondary_storage.set("oauth:code:old-code", json.dumps(data))
    return "old-code"


def _capture_login(
    auth: CrossAuth,
) -> tuple[list[BeforeLoginEvent], list[AfterLoginEvent]]:
    before: list[BeforeLoginEvent] = []
    after: list[AfterLoginEvent] = []
    auth.before("login")(before.append)
    auth.after("login")(after.append)
    return before, after


@pytest.fixture
def issued() -> list[TokenIssueRequest]:
    return []


@pytest.fixture
def issuer_auth(build_auth, issued: list[TokenIssueRequest]) -> CrossAuth:
    def token_issuer(request: TokenIssueRequest) -> tuple[str, int]:
        issued.append(request)
        return "app-token", 900

    return build_auth(
        oauth_server=replace(LEGACY_APP_OAUTH_SERVER, token_issuer=token_issuer)
    )


# --- Sessions Cross Auth creates ---------------------------------------------


@respx.mock
def test_browser_login_records_the_provider(
    auth: CrossAuth, session_storage: MemorySessionStorage
):
    before, after = _capture_login(auth)

    with _client(auth) as client:
        resp = _browser_login(client)

    assert resp.status_code == 302
    (record,) = session_storage.records.values()
    assert record.login_method == "fake"
    assert [event.login_method for event in before + after] == ["fake", "fake"]


@respx.mock
def test_login_hooks_can_override_the_login_method(
    auth: CrossAuth, session_storage: MemorySessionStorage
):
    _, after = _capture_login(auth)

    @auth.before("login")
    def rename(event: BeforeLoginEvent) -> BeforeLoginEvent:
        assert event.login_method == "fake"
        return replace(event, login_method="sso")

    with _client(auth) as client:
        _browser_login(client)

    (record,) = session_storage.records.values()
    assert record.login_method == "sso"
    (after_event,) = after
    assert after_event.login_method == "sso"


@respx.mock
def test_authorization_code_carries_the_provider_to_the_session(
    auth: CrossAuth,
    secondary_storage: SecondaryStorage,
    session_storage: MemorySessionStorage,
):
    with _client(auth) as client:
        code = _authorization_code(client)
        stored = secondary_storage.get(f"oauth:code:{code}")
        assert stored is not None
        grant = AuthorizationCodeGrantData.model_validate_json(stored)
        assert grant.login_method == "fake"

        resp = _redeem(client, code)

    assert resp.status_code == 200
    (record,) = session_storage.records.values()
    assert record.login_method == "fake"


def test_password_grant_records_password(
    build_auth, session_storage: MemorySessionStorage
):
    auth = build_auth(oauth_server=LEGACY_APP_OAUTH_SERVER)
    with _client(auth) as client:
        resp = _password_grant(client)

    assert resp.status_code == 200
    (record,) = session_storage.records.values()
    assert record.login_method == "password"


def test_authorization_code_without_login_method_still_redeems(
    auth: CrossAuth,
    secondary_storage: SecondaryStorage,
    session_storage: MemorySessionStorage,
):
    code = _store_code_without_login_method(secondary_storage)

    with _client(auth) as client:
        resp = _redeem(client, code)

    assert resp.status_code == 200
    (record,) = session_storage.records.values()
    assert record.login_method is None


# --- Application token_issuer ------------------------------------------------


@respx.mock
def test_token_issuer_reads_the_provider_from_the_authorization_code(
    issuer_auth: CrossAuth,
    issued: list[TokenIssueRequest],
    session_storage: MemorySessionStorage,
):
    before, after = _capture_login(issuer_auth)

    with _client(issuer_auth) as client:
        resp = _redeem(client, _authorization_code(client))

    (before_event,) = before
    assert (before_event.login_method, before_event.metadata) == ("fake", None)
    assert after[0].login_method == "fake"

    assert resp.status_code == 200
    (request,) = issued
    assert request.grant_type == "authorization_code"
    assert request.login_method == "fake"
    assert session_storage.records == {}


def test_token_issuer_reads_password_from_the_password_grant(
    issuer_auth: CrossAuth, issued: list[TokenIssueRequest]
):
    with _client(issuer_auth) as client:
        resp = _password_grant(client)

    assert resp.status_code == 200
    (request,) = issued
    assert request.login_method == "password"


def test_token_issuer_gets_none_for_an_older_authorization_code(
    issuer_auth: CrossAuth,
    issued: list[TokenIssueRequest],
    secondary_storage: SecondaryStorage,
):
    code = _store_code_without_login_method(secondary_storage)

    with _client(issuer_auth) as client:
        resp = _redeem(client, code)

    assert resp.status_code == 200
    (request,) = issued
    assert request.login_method is None


def test_token_issuer_gets_the_login_method_hooks_approved(
    issuer_auth: CrossAuth, issued: list[TokenIssueRequest]
):
    _, after = _capture_login(issuer_auth)

    @issuer_auth.before("login")
    def rename(event: BeforeLoginEvent) -> BeforeLoginEvent:
        return replace(event, login_method="legacy-password")

    with _client(issuer_auth) as client:
        resp = _password_grant(client)

    assert resp.status_code == 200
    (request,) = issued
    assert request.login_method == "legacy-password"
    (after_event,) = after
    assert after_event.login_method == "legacy-password"


@respx.mock
def test_login_hooks_can_deny_a_login_method(
    issuer_auth: CrossAuth, issued: list[TokenIssueRequest]
):
    @issuer_auth.before("login")
    def no_passwords(event: BeforeLoginEvent) -> None:
        if event.login_method == "password":
            raise CrossAuthException("access_denied", "Sign in with a provider")

    with _client(issuer_auth) as client:
        denied = _password_grant(client)
        allowed = _redeem(client, _authorization_code(client))

    assert denied.status_code == 400
    assert denied.json()["error"] == "access_denied"
    assert allowed.status_code == 200
    assert [request.login_method for request in issued] == ["fake"]


# --- Sessions the application creates ----------------------------------------


def test_application_sessions_take_the_login_method_argument(
    auth: CrossAuth, session_storage: MemorySessionStorage
):
    before, _ = _capture_login(auth)

    _, bearer = auth.issue_session_token("test", login_method="passkey")
    auth.login("test", response=FastAPIResponse(), login_method="password")
    auth.issue_session_token("test")

    assert bearer.login_method == "passkey"
    assert [record.login_method for record in session_storage.records.values()] == [
        "passkey",
        "password",
        None,
    ]
    assert [event.login_method for event in before] == ["passkey", "password", None]
