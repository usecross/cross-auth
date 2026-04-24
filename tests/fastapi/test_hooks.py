import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Any, cast
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from cross_web import AsyncHTTPRequest, Response as CrossWebResponse
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from respx import MockRouter

from cross_auth._auth_flow import AuthRequest, LinkCodeData
from cross_auth._issuer import AuthorizationCodeGrantData
from cross_auth._session import get_session
from cross_auth.exceptions import CrossAuthException
from cross_auth.fastapi import CrossAuth
from cross_auth.hooks import (
    AfterAuthenticateEvent,
    AfterLoginEvent,
    AfterLogoutEvent,
    AfterOAuthAuthorizeEvent,
    AfterOAuthCallbackEvent,
    AfterOAuthFinalizeLinkEvent,
    AfterOAuthLinkEvent,
    AfterTokenAuthorizationCodeEvent,
    BeforeAuthenticateEvent,
    BeforeLoginEvent,
    BeforeLogoutEvent,
    BeforeOAuthAuthorizeEvent,
    BeforeOAuthCallbackEvent,
    BeforeOAuthFinalizeLinkEvent,
    BeforeTokenPasswordEvent,
    HookRegistry,
)
from cross_auth.social_providers.oauth import (
    OAuth2Provider,
    ValidatedUserInfo,
)

from ..conftest import TEST_PASSWORD
from ..providers.conftest import TestOAuth2Provider


@pytest.fixture
def oauth_provider() -> TestOAuth2Provider:
    return TestOAuth2Provider(
        client_id="test_client_id",
        client_secret="test_client_secret",
    )


def _make_auth(
    secondary_storage,
    accounts_storage,
    *,
    providers: list[OAuth2Provider] | None = None,
    get_user_from_request=None,
    config=None,
) -> CrossAuth:
    return CrossAuth(
        providers=providers if providers is not None else [],
        storage=secondary_storage,
        accounts_storage=accounts_storage,
        create_token=lambda user_id: (f"token-{user_id}", 0),
        trusted_origins=["valid-frontend.com"],
        get_user_from_request=get_user_from_request,
        config=config,
    )


def test_authenticate_hooks(
    secondary_storage,
    accounts_storage,
):
    auth = _make_auth(secondary_storage, accounts_storage)
    seen: dict[str, str | None] = {}

    @auth.before("authenticate")
    def normalize_email(event: BeforeAuthenticateEvent) -> BeforeAuthenticateEvent:
        return replace(event, email=event.email.strip().lower())

    @auth.after("authenticate")
    def capture_user(event: AfterAuthenticateEvent) -> None:
        seen["user_id"] = None if event.user is None else str(event.user.id)

    user = auth.authenticate("  TEST@example.com  ", TEST_PASSWORD)

    assert user is not None
    assert user.email == "test@example.com"
    assert seen == {"user_id": "test"}


def test_login_hooks_mutate_user_id_and_response(
    secondary_storage,
    accounts_storage,
):
    auth = _make_auth(secondary_storage, accounts_storage)
    app = FastAPI()

    @auth.before("login")
    def map_service_user(event: BeforeLoginEvent) -> BeforeLoginEvent:
        return replace(event, user_id="test")

    @auth.after("login")
    def add_session_header(event: AfterLoginEvent) -> None:
        assert isinstance(event.response, CrossWebResponse)
        event.response.headers = {
            **(event.response.headers or {}),
            "X-Session-User": event.user_id,
        }

    @app.post("/login")
    def login() -> JSONResponse:
        response = JSONResponse({"ok": True})
        auth.login("svc_test", response=response)
        return response

    with TestClient(app) as client:
        resp = client.post("/login")

    session_id = resp.cookies.get("session_id")
    assert session_id is not None
    assert resp.headers["x-session-user"] == "test"

    session = get_session(session_id, secondary_storage)
    assert session is not None
    assert session.user_id == "test"


def test_logout_hooks(
    secondary_storage,
    accounts_storage,
):
    auth = _make_auth(secondary_storage, accounts_storage)
    seen: dict[str, str | None] = {}
    session_response = Response()
    auth.login("test", response=session_response)
    session_cookie = session_response.headers["set-cookie"].split(";", 1)[0]
    session_id = session_cookie.split("=", 1)[1]

    @auth.before("logout")
    def capture_before(event: BeforeLogoutEvent) -> None:
        assert isinstance(event.request, AsyncHTTPRequest)
        assert isinstance(event.response, CrossWebResponse)
        seen["before"] = event.session_id

    @auth.after("logout")
    def capture_after(event: AfterLogoutEvent) -> None:
        assert isinstance(event.request, AsyncHTTPRequest)
        assert isinstance(event.response, CrossWebResponse)
        seen["after"] = event.session_id

    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/logout",
            "headers": [(b"cookie", f"session_id={session_id}".encode())],
        }
    )

    response = Response()
    auth.logout(request, response=response)

    assert seen == {"before": session_id, "after": session_id}
    assert get_session(session_id, secondary_storage) is None


def test_logout_hooks_without_session_cookie(
    secondary_storage,
    accounts_storage,
    monkeypatch,
):
    auth = _make_auth(secondary_storage, accounts_storage)
    seen: dict[str, str | None] = {}
    delete_calls: list[str] = []

    def fail_if_delete_session_is_called(session_id, storage) -> None:
        delete_calls.append(session_id)

    monkeypatch.setattr(
        "cross_auth.fastapi.delete_session",
        fail_if_delete_session_is_called,
    )

    @auth.before("logout")
    def capture_before(event: BeforeLogoutEvent) -> None:
        seen["before"] = event.session_id

    @auth.after("logout")
    def capture_after(event: AfterLogoutEvent) -> None:
        seen["after"] = event.session_id

    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/logout",
            "headers": [],
        }
    )

    response = Response()
    auth.logout(request, response=response)

    assert seen == {"before": None, "after": None}
    assert delete_calls == []


def test_sync_events_reject_async_hooks(
    secondary_storage,
    accounts_storage,
):
    auth = _make_auth(secondary_storage, accounts_storage)

    with pytest.raises(
        TypeError, match="login hooks for sync events must be synchronous"
    ):

        async def invalid_hook(event: BeforeLoginEvent) -> None:  # pragma: no cover
            return None

        auth.before("login")(cast(Any, invalid_hook))


@pytest.mark.asyncio
async def test_policy_only_before_hooks_reject_replacement():
    hooks = HookRegistry()
    event = BeforeTokenPasswordEvent(
        client_id="client",
        username="user@example.com",
        user=None,
        scope=None,
    )

    async def replace_event(
        event: BeforeTokenPasswordEvent,
    ) -> BeforeTokenPasswordEvent:
        return event

    hooks.register_before(
        "token.password",
        cast(Any, replace_event),
        allow_async=True,
    )

    with pytest.raises(TypeError, match="token.password before hooks must return None"):
        await hooks.run_before_async("token.password", event)


@pytest.mark.asyncio
async def test_oauth_authorize_hooks(
    secondary_storage,
    accounts_storage,
    oauth_provider,
):
    auth = _make_auth(
        secondary_storage,
        accounts_storage,
        providers=[oauth_provider],
    )
    seen: dict[str, str] = {}

    @auth.before("oauth.authorize")
    async def apply_login_hint(
        event: BeforeOAuthAuthorizeEvent,
    ) -> BeforeOAuthAuthorizeEvent:
        return replace(event, login_hint="hooked@example.com")

    @auth.after("oauth.authorize")
    async def capture_authorization_url(event: AfterOAuthAuthorizeEvent) -> None:
        seen["authorization_url"] = event.authorization_url
        seen["state"] = event.state

    app = FastAPI()
    app.include_router(auth.router)

    with TestClient(app) as client:
        resp = client.get(
            "/test/authorize",
            params={
                "client_id": "original-client",
                "redirect_uri": "http://valid-frontend.com/callback",
                "response_type": "code",
                "code_challenge": "test",
                "code_challenge_method": "S256",
            },
            follow_redirects=False,
        )

    assert resp.status_code == 302
    assert seen["authorization_url"] == resp.headers["location"]
    assert parse_qs(urlparse(resp.headers["location"]).query)["login_hint"] == [
        "hooked@example.com"
    ]

    stored = secondary_storage.get(f"oauth:authorization_request:{seen['state']}")
    assert stored is not None
    assert json.loads(stored)["client_id"] == "original-client"


@pytest.mark.asyncio
async def test_oauth_callback_hooks(
    secondary_storage,
    accounts_storage,
    oauth_provider,
    respx_mock: MockRouter,
):
    auth = _make_auth(
        secondary_storage,
        accounts_storage,
        providers=[oauth_provider],
    )
    seen: dict[str, str] = {}

    secondary_storage.set(
        "oauth:authorization_request:test_state",
        AuthRequest(
            flow="token",
            provider_id=oauth_provider.id,
            state="test_state",
            provider_code_verifier="test_provider_verifier",
            client_id="my_app_client_id",
            client_redirect_uri="http://valid-frontend.com/callback",
            client_state="client-state",
            client_code_challenge="test",
            client_code_challenge_method="S256",
        ).model_dump_json(),
    )

    @auth.before("oauth.callback")
    async def rewrite_email(
        event: BeforeOAuthCallbackEvent,
    ) -> BeforeOAuthCallbackEvent:
        user_info = {
            **event.user_info,
            "email": "hooked@example.com",
        }
        validated = ValidatedUserInfo(
            email="hooked@example.com",
            provider_user_id=event.validated_user_info.provider_user_id,
            email_verified=event.validated_user_info.email_verified,
        )
        return replace(event, user_info=user_info, validated_user_info=validated)

    @auth.after("oauth.callback")
    async def capture_created_user(event: AfterOAuthCallbackEvent) -> None:
        if event.created_user is not None:
            seen["email"] = event.created_user.email

    respx_mock.post(oauth_provider.token_endpoint).mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "access-token",
                "token_type": "Bearer",
                "scope": "openid email profile",
            },
        )
    )
    respx_mock.get(oauth_provider.user_info_endpoint).mock(
        return_value=httpx.Response(
            200,
            json={
                "email": "new-user@example.com",
                "email_verified": True,
                "id": "provider-user-id",
            },
        )
    )

    app = FastAPI()
    app.include_router(auth.router)

    with TestClient(app) as client:
        resp = client.get(
            "/test/callback",
            params={"code": "oauth-code", "state": "test_state"},
            follow_redirects=False,
        )

    assert resp.status_code == 302
    assert seen == {"email": "hooked@example.com"}
    assert accounts_storage.find_user_by_email("hooked@example.com") is not None


@pytest.mark.asyncio
async def test_oauth_callback_hooks_run_for_session_flow(
    secondary_storage,
    accounts_storage,
    oauth_provider,
    respx_mock: MockRouter,
):
    auth = _make_auth(
        secondary_storage,
        accounts_storage,
        providers=[oauth_provider],
    )
    seen: dict[str, str] = {}

    @auth.before("oauth.callback")
    async def rewrite_session_email(
        event: BeforeOAuthCallbackEvent,
    ) -> BeforeOAuthCallbackEvent:
        user_info = {
            **event.user_info,
            "email": "session-hooked@example.com",
        }
        validated = ValidatedUserInfo(
            email="session-hooked@example.com",
            provider_user_id=event.validated_user_info.provider_user_id,
            email_verified=event.validated_user_info.email_verified,
        )
        return replace(event, user_info=user_info, validated_user_info=validated)

    @auth.after("oauth.callback")
    async def capture_session_callback(event: AfterOAuthCallbackEvent) -> None:
        assert event.authorization_code is None
        assert event.redirect_uri is None
        if event.created_user is not None:
            seen["email"] = event.created_user.email

    respx_mock.post(oauth_provider.token_endpoint).mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "access-token",
                "token_type": "Bearer",
                "scope": "openid email profile",
            },
        )
    )
    respx_mock.get(oauth_provider.user_info_endpoint).mock(
        return_value=httpx.Response(
            200,
            json={
                "email": "new-session-user@example.com",
                "email_verified": True,
                "id": "session-provider-user-id",
            },
        )
    )

    app = FastAPI()
    app.include_router(auth.router)

    with TestClient(app) as client:
        start = client.get("/test/login", follow_redirects=False)
        state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]
        resp = client.get(
            "/test/callback",
            params={"code": "oauth-code", "state": state},
            follow_redirects=False,
        )

    session_id = resp.cookies.get("session_id")
    assert resp.status_code == 302
    assert session_id is not None
    assert seen == {"email": "session-hooked@example.com"}
    assert accounts_storage.find_user_by_email("session-hooked@example.com") is not None

    session = get_session(session_id, secondary_storage)
    assert session is not None
    assert session.user_id == "session-provider-user-id"


@pytest.mark.asyncio
async def test_login_hooks_run_for_oauth_session_flow(
    secondary_storage,
    accounts_storage,
    oauth_provider,
    respx_mock: MockRouter,
):
    auth = _make_auth(
        secondary_storage,
        accounts_storage,
        providers=[oauth_provider],
    )
    seen: dict[str, str] = {}

    @auth.before("login")
    def capture_oauth_login(event: BeforeLoginEvent) -> None:
        seen["before_user_id"] = event.user_id

    @auth.after("login")
    def add_oauth_login_header(event: AfterLoginEvent) -> None:
        seen["after_user_id"] = event.user_id
        event.response.headers = {
            **(event.response.headers or {}),
            "X-OAuth-Session-User": event.user_id,
        }

    respx_mock.post(oauth_provider.token_endpoint).mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "access-token",
                "token_type": "Bearer",
                "scope": "openid email profile",
            },
        )
    )
    respx_mock.get(oauth_provider.user_info_endpoint).mock(
        return_value=httpx.Response(
            200,
            json={
                "email": "oauth-session@example.com",
                "email_verified": True,
                "id": "oauth-session-user-id",
            },
        )
    )

    app = FastAPI()
    app.include_router(auth.router)

    with TestClient(app) as client:
        start = client.get("/test/login", follow_redirects=False)
        state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]
        resp = client.get(
            "/test/callback",
            params={"code": "oauth-code", "state": state},
            follow_redirects=False,
        )

    session_id = resp.cookies.get("session_id")
    assert resp.status_code == 302
    assert resp.headers["x-oauth-session-user"] == "oauth-session-user-id"
    assert session_id is not None
    assert seen == {
        "before_user_id": "oauth-session-user-id",
        "after_user_id": "oauth-session-user-id",
    }

    session = get_session(session_id, secondary_storage)
    assert session is not None
    assert session.user_id == "oauth-session-user-id"


@pytest.mark.asyncio
async def test_oauth_link_hooks(
    secondary_storage,
    accounts_storage,
    logged_in_user,
    oauth_provider,
):
    auth = _make_auth(
        secondary_storage,
        accounts_storage,
        providers=[oauth_provider],
        get_user_from_request=lambda request: (
            logged_in_user
            if request.headers.get("Authorization") == "Bearer test"
            else None
        ),
        config={"account_linking": {"enabled": True}},
    )
    seen: dict[str, str] = {}

    @auth.after("oauth.link")
    async def capture_state(event: AfterOAuthLinkEvent) -> None:
        seen["state"] = event.state
        seen["authorization_url"] = event.authorization_url

    app = FastAPI()
    app.include_router(auth.router)

    with TestClient(app) as client:
        resp = client.post(
            "/test/link",
            headers={"Authorization": "Bearer test"},
            json={
                "redirect_uri": "http://valid-frontend.com/callback",
                "code_challenge": "test",
                "code_challenge_method": "S256",
                "client_id": "test-client",
            },
        )

    assert resp.status_code == 200
    assert resp.json()["authorization_url"] == seen["authorization_url"]
    assert (
        secondary_storage.get(f"oauth:authorization_request:{seen['state']}")
        is not None
    )


@pytest.mark.asyncio
async def test_oauth_finalize_link_hooks(
    secondary_storage,
    accounts_storage,
    logged_in_user,
    oauth_provider,
    respx_mock: MockRouter,
):
    auth = _make_auth(
        secondary_storage,
        accounts_storage,
        providers=[oauth_provider],
        get_user_from_request=lambda request: (
            logged_in_user
            if request.headers.get("Authorization") == "Bearer test"
            else None
        ),
        config={"account_linking": {"enabled": True}},
    )
    seen: dict[str, bool] = {}

    secondary_storage.set(
        "oauth:link_request:test-link-code",
        LinkCodeData(
            expires_at=datetime.now(tz=timezone.utc) + timedelta(minutes=10),
            client_id="test-client",
            redirect_uri="http://valid-frontend.com/callback",
            code_challenge="n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
            code_challenge_method="S256",
            user_id=str(logged_in_user.id),
            provider_code="provider-code",
        ).model_dump_json(),
    )

    @auth.before("oauth.finalize_link")
    async def disable_login_method(
        event: BeforeOAuthFinalizeLinkEvent,
    ) -> BeforeOAuthFinalizeLinkEvent:
        return replace(event, allow_login=False)

    @auth.after("oauth.finalize_link")
    async def capture_login_mode(event: AfterOAuthFinalizeLinkEvent) -> None:
        seen["is_login_method"] = event.social_account.is_login_method

    respx_mock.post(oauth_provider.token_endpoint).mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "access-token",
                "token_type": "Bearer",
                "scope": "openid email profile",
            },
        )
    )
    respx_mock.get(oauth_provider.user_info_endpoint).mock(
        return_value=httpx.Response(
            200,
            json={
                "email": logged_in_user.email,
                "email_verified": True,
                "id": "provider-user-id",
            },
        )
    )

    app = FastAPI()
    app.include_router(auth.router)

    with TestClient(app) as client:
        resp = client.post(
            "/test/finalize-link",
            headers={"Authorization": "Bearer test"},
            json={"link_code": "test-link-code", "code_verifier": "test"},
        )

    assert resp.status_code == 200
    assert seen == {"is_login_method": False}


@pytest.mark.asyncio
async def test_token_hooks(
    secondary_storage,
    accounts_storage,
):
    auth = _make_auth(secondary_storage, accounts_storage)
    blocked = False
    seen: dict[str, str] = {}

    @auth.before("token.password")
    async def block_legacy_password_grant(event: BeforeTokenPasswordEvent) -> None:
        nonlocal blocked
        blocked = True
        if event.client_id == "legacy-spa":
            raise CrossAuthException(
                "unauthorized_client",
                "Password grant disabled",
            )

    @auth.after("token.authorization_code")
    async def capture_auth_code_token(event: AfterTokenAuthorizationCodeEvent) -> None:
        seen["access_token"] = event.token_response.access_token
        raise CrossAuthException("invalid_grant", "ignored after hook failure")

    secondary_storage.set(
        "oauth:code:test-code",
        AuthorizationCodeGrantData(
            user_id="test",
            expires_at=datetime.now(tz=timezone.utc) + timedelta(minutes=10),
            client_id="test",
            redirect_uri="test",
            code_challenge="n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
            code_challenge_method="S256",
        ).model_dump_json(),
    )

    app = FastAPI()
    app.include_router(auth.router)

    with TestClient(app) as client:
        blocked_resp = client.post(
            "/token",
            data={
                "grant_type": "password",
                "client_id": "legacy-spa",
                "username": "test@example.com",
                "password": TEST_PASSWORD,
            },
        )
        success_resp = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": "test",
                "code": "test-code",
                "redirect_uri": "test",
                "code_verifier": "test",
            },
        )

    assert blocked is True
    assert blocked_resp.status_code == 400
    assert blocked_resp.json() == {
        "error": "unauthorized_client",
        "error_description": "Password grant disabled",
    }
    assert success_resp.status_code == 200
    assert seen == {"access_token": "token-test"}
