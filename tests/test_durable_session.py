from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from unittest import mock

import pytest
import time_machine
from cross_web import HTTPRequest, TestingHTTPRequestAdapter
from fastapi import Depends, FastAPI, Request, Response
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from inline_snapshot import snapshot

from cross_auth._config import Config
from cross_auth._context import Context
from cross_auth._issuer import AuthorizationCodeGrantData, Issuer
from cross_auth._session import (
    SessionConfig,
    create_session,
    delete_session,
    get_current_session,
    get_current_user,
    get_session,
    hash_session_token,
)
from cross_auth._storage import AccountsStorage, SecondaryStorage
from cross_auth.fastapi import CrossAuth

from .conftest import MemorySessionStorage

NOW = datetime(2026, 5, 24, 12, 0, tzinfo=timezone.utc)


def _request(
    *,
    cookies: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    post_data: dict[str, str] | None = None,
) -> HTTPRequest:
    return HTTPRequest(
        TestingHTTPRequestAdapter(
            cookies=cookies,
            headers=headers,
            post_data=post_data,
        )
    )


def _make_auth(
    *,
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: MemorySessionStorage | None,
    config: Config | None = None,
) -> CrossAuth:
    return CrossAuth(
        providers=[],
        storage=secondary_storage,
        accounts_storage=accounts_storage,
        session_storage=session_storage,
        trusted_origins=[],
        config=config,
    )


@time_machine.travel(NOW, tick=False)
def test_create_session_hashes_token_and_stores_metadata(
    session_storage: MemorySessionStorage,
):
    session_token, record = create_session(
        "test",
        session_storage,
        max_age=3600,
        metadata={
            "client_id": "web",
            "client_name": "Example Web",
            "user_agent": "Mozilla/5.0",
            "ip": "203.0.113.10",
        },
    )

    assert session_token
    assert record.user_id == "test"
    assert record.created_at == NOW
    assert record.updated_at == NOW
    assert record.last_active_at == NOW
    assert record.expires_at == NOW + timedelta(seconds=3600)
    assert record.client_id == "web"
    assert record.client_name == "Example Web"
    assert record.user_agent == "Mozilla/5.0"
    assert record.ip == "203.0.113.10"

    stored = next(iter(session_storage.records.values()))
    assert stored.token_hash == hash_session_token(session_token)
    assert stored.token_hash != session_token


@time_machine.travel(NOW, tick=False)
def test_lookup_rejects_expired_and_revoked_sessions_without_deleting_records(
    session_storage: MemorySessionStorage,
):
    expired_token, expired_record = create_session("test", session_storage, max_age=1)
    revoked_token, revoked_record = create_session(
        "test", session_storage, max_age=3600
    )

    with time_machine.travel(NOW + timedelta(seconds=2), tick=False):
        assert get_session(expired_token, session_storage) is None

    assert session_storage.get_any(expired_record.id) is expired_record

    with time_machine.travel(NOW + timedelta(seconds=3), tick=False):
        delete_session(revoked_token, session_storage)
        assert get_session(revoked_token, session_storage) is None

    assert session_storage.get_any(revoked_record.id) is revoked_record
    assert revoked_record.revoked_at == NOW + timedelta(seconds=3)


@time_machine.travel(NOW, tick=False)
def test_get_current_user_resolves_cookie_then_bearer_and_refreshes(
    accounts_storage: AccountsStorage,
    session_storage: MemorySessionStorage,
):
    config: SessionConfig = {"max_age": 60, "update_age": 10}

    cookie_token, cookie_record = create_session("test", session_storage, max_age=60)
    bearer_token, bearer_record = create_session("test", session_storage, max_age=60)

    cookie_request = _request(cookies={"session_id": cookie_token})
    bearer_request = _request(headers={"Authorization": f"Bearer {bearer_token}"})

    with time_machine.travel(NOW + timedelta(seconds=11), tick=False):
        user = get_current_user(
            cookie_request,
            session_storage,
            accounts_storage,
            config,
        )
        current_session = get_current_session(
            bearer_request,
            session_storage,
            config,
        )

    assert user is not None
    assert user.id == "test"
    assert cookie_record.updated_at == NOW + timedelta(seconds=11)
    assert cookie_record.expires_at == NOW + timedelta(seconds=71)
    assert cookie_record.last_active_at == NOW + timedelta(seconds=11)
    assert current_session is bearer_record


@time_machine.travel(NOW, tick=False)
def test_cross_auth_management_apis_enforce_ownership_and_revoke_sessions(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: MemorySessionStorage,
):
    auth = _make_auth(
        secondary_storage=secondary_storage,
        accounts_storage=accounts_storage,
        session_storage=session_storage,
    )

    _, current_record = create_session("test", session_storage, max_age=3600)
    with time_machine.travel(NOW + timedelta(seconds=1), tick=False):
        _, other_record = create_session("test", session_storage, max_age=3600)
    with time_machine.travel(NOW + timedelta(seconds=2), tick=False):
        _, different_user_record = create_session(
            "different", session_storage, max_age=3600
        )

    listed = auth.list_sessions("test")
    assert [record.id for record in listed.records] == [
        other_record.id,
        current_record.id,
    ]
    assert auth.get_session(different_user_record.id, user_id="test") is None

    with time_machine.travel(NOW + timedelta(seconds=1), tick=False):
        auth.revoke_session(other_record.id, user_id="test")
    assert other_record.revoked_at == NOW + timedelta(seconds=1)

    with time_machine.travel(NOW + timedelta(seconds=2), tick=False):
        revoked = auth.revoke_other_sessions(
            user_id="test",
            keep_session_id=current_record.id,
        )
    assert revoked == 0
    assert current_record.revoked_at is None

    with time_machine.travel(NOW + timedelta(seconds=3), tick=False):
        revoked = auth.revoke_all_sessions(user_id="test")
    assert revoked == 1
    assert current_record.revoked_at == NOW + timedelta(seconds=3)
    assert different_user_record.revoked_at is None


def test_cross_auth_allows_missing_session_storage(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
):
    auth = _make_auth(
        secondary_storage=secondary_storage,
        accounts_storage=accounts_storage,
        session_storage=None,
    )

    # Session-management methods require session_storage and must fail clearly.
    response = Response()
    with pytest.raises(RuntimeError, match="session_storage is required"):
        auth.login("test", response=response)


def test_cookie_auth_without_session_storage_fails_fast(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
):
    with pytest.raises(ValueError, match="cookies"):
        _make_auth(
            secondary_storage=secondary_storage,
            accounts_storage=accounts_storage,
            session_storage=None,
            config={"session": {"cookies": {"auth": True}}},
        )


def test_after_login_event_exposes_only_session_record_and_cookie(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: MemorySessionStorage,
):
    auth = _make_auth(
        secondary_storage=secondary_storage,
        accounts_storage=accounts_storage,
        session_storage=session_storage,
    )
    seen: list[Any] = []

    @auth.after("login")
    def capture(event):
        seen.append(event)

    app = FastAPI()

    @app.post("/login")
    def login(request: Request):
        response = JSONResponse({"ok": True})
        auth.login(
            "test",
            response=response,
            metadata={"user_agent": request.headers.get("User-Agent")},
        )
        return response

    with TestClient(app) as client:
        response = client.post("/login", headers={"User-Agent": "test-browser"})

    session_token = response.cookies["session_id"]
    assert len(seen) == 1
    event = seen[0]
    assert event.cookie.value == session_token
    assert event.session_record.user_agent == "test-browser"
    assert event.session_record.token_hash == hash_session_token(session_token)
    assert not hasattr(event, "session_token")
    assert not hasattr(event, "session_id")
    assert not hasattr(event, "session_data")
    assert not hasattr(event, "session_record_id")


@time_machine.travel(NOW, tick=False)
def test_authorization_code_token_endpoint_creates_session_with_session_storage(
    secondary_storage: SecondaryStorage,
    session_storage: MemorySessionStorage,
    context: Context,
):
    issuer = Issuer()
    code = "code-1"
    secondary_storage.set(
        f"oauth:code:{code}",
        AuthorizationCodeGrantData(
            user_id="test",
            expires_at=NOW + timedelta(seconds=60),
            client_id="ios-app",
            redirect_uri="https://client.example/callback",
            code_challenge="n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
            code_challenge_method="S256",
        ).model_dump_json(),
    )

    response = issuer.token(
        _request(
            headers={"User-Agent": "ios-app/1.0"},
            post_data={
                "grant_type": "authorization_code",
                "client_id": "ios-app",
                "code": code,
                "redirect_uri": "https://client.example/callback",
                "code_verifier": "test",
            },
        ),
        context,
    )

    assert response.status_code == 200
    assert response.json() == snapshot(
        {
            "access_token": mock.ANY,
            "token_type": "Bearer",
            "expires_in": 86400,
            "refresh_token": None,
            "refresh_token_expires_in": None,
            "scope": "",
            "id_token": None,
        }
    )
    assert [
        {
            "token_hash": record.token_hash,
            "user_id": record.user_id,
            "client_id": record.client_id,
            "user_agent": record.user_agent,
        }
        for record in session_storage.records.values()
    ] == snapshot(
        [
            {
                "token_hash": mock.ANY,
                "user_id": "test",
                "client_id": "ios-app",
                "user_agent": "ios-app/1.0",
            }
        ]
    )


@time_machine.travel(NOW, tick=False)
def test_password_token_endpoint_creates_session_with_session_storage(
    session_storage: MemorySessionStorage,
    context: Context,
):
    issuer = Issuer()

    response = issuer.token(
        _request(
            headers={"User-Agent": "ios-app/1.0"},
            post_data={
                "grant_type": "password",
                "client_id": "ios-app",
                "username": "test@example.com",
                "password": "password123",
            },
        ),
        context,
    )

    assert response.status_code == 200
    assert response.json() == snapshot(
        {
            "access_token": mock.ANY,
            "token_type": "Bearer",
            "expires_in": 86400,
            "refresh_token": None,
            "refresh_token_expires_in": None,
            "scope": "",
            "id_token": None,
        }
    )
    assert [
        {
            "token_hash": record.token_hash,
            "user_id": record.user_id,
            "client_id": record.client_id,
            "user_agent": record.user_agent,
        }
        for record in session_storage.records.values()
    ] == snapshot(
        [
            {
                "token_hash": mock.ANY,
                "user_id": "test",
                "client_id": "ios-app",
                "user_agent": "ios-app/1.0",
            }
        ]
    )


def test_token_endpoint_errors_without_token_issuer_or_session_storage(
    issuer: Issuer,
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    valid_code: str,
):
    context = Context(
        secondary_storage=secondary_storage,
        accounts_storage=accounts_storage,
        session_storage=None,
        get_user_from_request=lambda _: None,
        trusted_origins=["client.example"],
    )

    response = issuer.token(
        HTTPRequest.from_form_data(
            data={
                "grant_type": "authorization_code",
                "client_id": "test",
                "code": valid_code,
                "redirect_uri": "test",
                "code_verifier": "test",
            }
        ),
        context,
    )

    assert response.status_code == 400
    body = response.json()
    assert body == {
        "error": "server_error",
        "error_description": (
            "The token endpoint requires token_issuer or session_storage"
        ),
    }


def _sliding_app(auth: CrossAuth) -> FastAPI:
    app = FastAPI()

    @app.get("/me")
    def me(user: Any = Depends(auth.get_current_user)) -> dict[str, Any]:
        return {"user": None if user is None else user.id}

    return app


@time_machine.travel(NOW, tick=False)
def test_cookie_session_is_rolled_when_refreshed(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: MemorySessionStorage,
):
    auth = _make_auth(
        secondary_storage=secondary_storage,
        accounts_storage=accounts_storage,
        session_storage=session_storage,
        config={
            "session": {
                "max_age": 60,
                "update_age": 10,
                "cookies": {"secure": False},
            }
        },
    )
    token, record = create_session("test", session_storage, max_age=60)
    client = TestClient(_sliding_app(auth))

    # Within update_age: no refresh, so the cookie is left untouched.
    with time_machine.travel(NOW + timedelta(seconds=5), tick=False):
        resp = client.get("/me", cookies={"session_id": token})
    assert resp.json() == {"user": "test"}
    assert "set-cookie" not in resp.headers

    # Past update_age: the record rolls forward AND the cookie is reissued with
    # a fresh Max-Age so the browser copy slides too.
    with time_machine.travel(NOW + timedelta(seconds=20), tick=False):
        resp = client.get("/me", cookies={"session_id": token})
    assert resp.json() == {"user": "test"}
    set_cookie = resp.headers.get("set-cookie", "")
    assert "session_id=" in set_cookie
    assert "Max-Age=60" in set_cookie
    assert record.expires_at == NOW + timedelta(seconds=80)


@time_machine.travel(NOW, tick=False)
def test_bearer_session_refreshes_without_setting_cookie(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: MemorySessionStorage,
):
    auth = _make_auth(
        secondary_storage=secondary_storage,
        accounts_storage=accounts_storage,
        session_storage=session_storage,
        config={
            "session": {
                "max_age": 60,
                "update_age": 10,
                "cookies": {"secure": False},
            }
        },
    )
    token, record = create_session("test", session_storage, max_age=60)
    client = TestClient(_sliding_app(auth))

    # Bearer transport has no cookie to roll, but the record still slides.
    with time_machine.travel(NOW + timedelta(seconds=20), tick=False):
        resp = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.json() == {"user": "test"}
    assert "set-cookie" not in resp.headers
    assert record.expires_at == NOW + timedelta(seconds=80)
