from typing import Annotated

import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from cross_auth import (
    AccountsStorage,
    OAuth2Provider,
    OAuthServer,
    SecondaryStorage,
    SessionStorage,
    User,
)
from cross_auth._config import Config
from cross_auth._session import create_session, get_session
from cross_auth.fastapi import CrossAuth
from cross_auth.router import AuthRouter
from cross_auth.social_providers.github import GitHubProvider
from ..conftest import legacy_password_grant

TEST_PASSWORD = "password123"  # noqa: S105


def test_token_only_mode_without_session_storage(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
):
    auth = CrossAuth(
        providers=[],
        storage=secondary_storage,
        accounts_storage=accounts_storage,
    )
    assert auth.router is not None


def test_token_endpoint_uses_token_issuer_without_session_storage(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
):
    issued_requests = []

    def issue_token(request):
        issued_requests.append(request)
        return "stateless-token", 900

    auth = CrossAuth(
        providers=[],
        storage=secondary_storage,
        accounts_storage=accounts_storage,
        oauth_server=OAuthServer(token_issuer=issue_token, password_grant=True),
    )
    app = FastAPI()
    app.include_router(auth.router)

    with TestClient(app) as client:
        with legacy_password_grant():
            response = client.post(
                "/token",
                data={
                    "grant_type": "password",
                    "client_id": "mobile-app",
                    "username": "test@example.com",
                    "password": TEST_PASSWORD,
                },
            )

    assert response.status_code == 200
    assert response.json()["access_token"] == "stateless-token"
    assert response.json()["expires_in"] == 900

    [token_request] = issued_requests
    assert token_request.user_id == "test"
    assert token_request.client_id == "mobile-app"
    assert token_request.grant_type == "password"
    assert token_request.username == "test@example.com"


def test_get_current_session_requires_session_storage(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
):
    auth = CrossAuth(
        providers=[],
        storage=secondary_storage,
        accounts_storage=accounts_storage,
    )
    request = Request({"type": "http", "method": "GET", "path": "/", "headers": []})
    with pytest.raises(RuntimeError, match="session_storage is required"):
        auth.get_current_session(request)


def test_trusted_origins_is_deprecated(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
):
    message = "trusted_origins has no effect"
    with pytest.warns(DeprecationWarning, match=message) as auth_warnings:
        CrossAuth(
            providers=[],
            storage=secondary_storage,
            accounts_storage=accounts_storage,
            trusted_origins=[],
        )
    with pytest.warns(DeprecationWarning, match=message) as router_warnings:
        AuthRouter(
            providers=[],
            secondary_storage=secondary_storage,
            accounts_storage=accounts_storage,
            get_user_from_request=lambda _: None,
            trusted_origins=[],
        )

    # Attributed to the caller's code rather than to Cross-Auth.
    recorded = [*auth_warnings, *router_warnings]
    assert [warning.filename for warning in recorded] == [__file__, __file__]


def _make_auth(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
    **kwargs,
) -> CrossAuth:
    return CrossAuth(
        providers=[],
        storage=secondary_storage,
        accounts_storage=accounts_storage,
        session_storage=session_storage,
        **kwargs,
    )


def test_get_current_user(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth = _make_auth(secondary_storage, accounts_storage, session_storage)
    app = FastAPI()
    app.include_router(auth.router)

    @app.get("/me")
    def me(user: Annotated[User | None, Depends(auth.get_current_user)]):
        if user is None:
            return {"user": None}
        return {"user": user.id}

    session_id, _ = create_session("test", session_storage)

    with TestClient(app) as client:
        resp = client.get("/me", cookies={"session_id": session_id})
        assert resp.status_code == 200
        assert resp.json() == {"user": "test"}


def test_get_current_user_no_cookie(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth = _make_auth(secondary_storage, accounts_storage, session_storage)
    app = FastAPI()

    @app.get("/me")
    def me(user: Annotated[User | None, Depends(auth.get_current_user)]):
        return {"user": user}

    with TestClient(app) as client:
        resp = client.get("/me")
        assert resp.status_code == 200
        assert resp.json() == {"user": None}


def test_require_current_user(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth = _make_auth(secondary_storage, accounts_storage, session_storage)
    app = FastAPI()

    @app.get("/me")
    def me(user: Annotated[User, Depends(auth.require_current_user)]):
        return {"user": user.id}

    with TestClient(app) as client:
        resp = client.get("/me")
        assert resp.status_code == 401

    session_id, _ = create_session("test", session_storage)

    with TestClient(app) as client:
        resp = client.get("/me", cookies={"session_id": session_id})
        assert resp.status_code == 200
        assert resp.json() == {"user": "test"}


def test_get_current_user_custom_session_config(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth = _make_auth(
        secondary_storage,
        accounts_storage,
        session_storage,
        config={"session": {"cookies": {"name": "my_sid"}}},
    )
    app = FastAPI()

    @app.get("/me")
    def me(user: Annotated[User | None, Depends(auth.get_current_user)]):
        if user is None:
            return {"user": None}
        return {"user": user.id}

    session_id, _ = create_session("test", session_storage)

    with TestClient(app) as client:
        # Default cookie name should not work
        resp = client.get("/me", cookies={"session_id": session_id})
        assert resp.json() == {"user": None}

        # Custom cookie name should work
        resp = client.get("/me", cookies={"my_sid": session_id})
        assert resp.status_code == 200
        assert resp.json() == {"user": "test"}


def test_router_property(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth = _make_auth(secondary_storage, accounts_storage, session_storage)
    assert isinstance(auth.router, AuthRouter)

    app = FastAPI()
    app.include_router(auth.router)


def test_auto_wired_get_user_from_request(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    """Verify that when no get_user_from_request is provided, the router's
    context uses session-based lookup. We expose the context's callback
    through an endpoint that calls it directly."""
    auth = _make_auth(secondary_storage, accounts_storage, session_storage)

    session_id, _ = create_session("test", session_storage)

    app = FastAPI()
    app.include_router(auth.router)

    @app.get("/check")
    async def check(request: Request):
        user = auth.get_current_user(request)
        if user is None:
            return {"user": None}
        return {"user": user.id}

    with TestClient(app) as client:
        client.cookies.set("session_id", session_id)
        resp = client.get("/check")
        assert resp.status_code == 200
        assert resp.json() == {"user": "test"}


# --- Tests for new public API methods ---


def test_authenticate(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth = _make_auth(secondary_storage, accounts_storage, session_storage)
    user = auth.authenticate("test@example.com", TEST_PASSWORD)
    assert user is not None
    assert user.email == "test@example.com"


def test_authenticate_normalizes_email(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth = _make_auth(secondary_storage, accounts_storage, session_storage)
    user = auth.authenticate("  Test@Example.COM ", TEST_PASSWORD)
    assert user is not None
    assert user.email == "test@example.com"


def test_authenticate_wrong_password(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth = _make_auth(secondary_storage, accounts_storage, session_storage)
    result = auth.authenticate("test@example.com", "wrong-password")
    assert result is None


def test_login(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth = _make_auth(secondary_storage, accounts_storage, session_storage)
    app = FastAPI()

    @app.post("/do-login")
    def do_login():
        response = JSONResponse({"ok": True})
        auth.login("test", response=response)
        return response

    with TestClient(app) as client:
        resp = client.post("/do-login")
        assert resp.status_code == 200
        session_id = resp.cookies.get("session_id")
        assert session_id
        assert "HttpOnly" in resp.headers["set-cookie"]
        assert "Secure" in resp.headers["set-cookie"]
        assert "SameSite=lax" in resp.headers["set-cookie"]
        assert "Path=/" in resp.headers["set-cookie"]


def test_login_preserves_existing_response_cookies(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth = _make_auth(secondary_storage, accounts_storage, session_storage)
    app = FastAPI()

    @app.post("/do-login")
    def do_login():
        response = JSONResponse({"ok": True})
        response.set_cookie("first", "1")
        response.set_cookie("second", "2")
        auth.login("test", response=response)
        return response

    with TestClient(app) as client:
        resp = client.post("/do-login")

    set_cookie_headers = resp.headers.get_list("set-cookie")
    assert any(header.startswith("first=1;") for header in set_cookie_headers)
    assert any(header.startswith("second=2;") for header in set_cookie_headers)
    assert any(header.startswith("session_id=") for header in set_cookie_headers)


def test_login_custom_session_config(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth = _make_auth(
        secondary_storage,
        accounts_storage,
        session_storage,
        config={"session": {"max_age": 3600, "cookies": {"name": "my_sid"}}},
    )
    app = FastAPI()

    @app.post("/do-login")
    def do_login():
        response = JSONResponse({"ok": True})
        auth.login("test", response=response)
        return response

    with TestClient(app) as client:
        resp = client.post("/do-login")
        assert resp.status_code == 200
        assert resp.cookies.get("my_sid")
        assert "Max-Age=3600" in resp.headers["set-cookie"]


def test_login_creates_valid_session(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth = _make_auth(secondary_storage, accounts_storage, session_storage)
    app = FastAPI()

    @app.post("/do-login")
    def do_login():
        response = JSONResponse({"ok": True})
        result = auth.login("test", response=response)
        assert result is None  # response-based API returns None
        return response

    with TestClient(app) as client:
        resp = client.post("/do-login")
        session_id = resp.cookies.get("session_id")
        assert session_id

    # The session should be retrievable.
    session = get_session(session_id, session_storage)
    assert session is not None
    assert session.user_id == "test"


def test_logout(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth = _make_auth(secondary_storage, accounts_storage, session_storage)
    app = FastAPI()
    app.include_router(auth.router)

    # Create a session first.
    session_id, _ = create_session("test", session_storage)

    @app.post("/do-logout")
    def do_logout(request: Request):
        response = JSONResponse({"ok": True})
        result = auth.logout(request, response=response)
        assert result is None  # response-based API returns None
        return response

    with TestClient(app) as client:
        client.cookies.set("session_id", session_id)
        resp = client.post("/do-logout")
        assert resp.status_code == 200
        assert resp.json() == {"ok": True}
        assert "session_id=" in resp.headers["set-cookie"]
        assert "Max-Age=0" in resp.headers["set-cookie"]

    # Session should be deleted
    assert get_session(session_id, session_storage) is None


def test_logout_preserves_existing_response_cookies(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth = _make_auth(secondary_storage, accounts_storage, session_storage)
    app = FastAPI()
    session_id, _ = create_session("test", session_storage)

    @app.post("/do-logout")
    def do_logout(request: Request):
        response = JSONResponse({"ok": True})
        response.set_cookie("first", "1")
        response.set_cookie("second", "2")
        auth.logout(request, response=response)
        return response

    with TestClient(app) as client:
        client.cookies.set("session_id", session_id)
        resp = client.post("/do-logout")

    set_cookie_headers = resp.headers.get_list("set-cookie")
    assert any(header.startswith("first=1;") for header in set_cookie_headers)
    assert any(header.startswith("second=2;") for header in set_cookie_headers)
    assert any(header.startswith("session_id=") for header in set_cookie_headers)


def test_logout_no_session_cookie(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth = _make_auth(secondary_storage, accounts_storage, session_storage)
    app = FastAPI()

    @app.post("/logout")
    def do_logout(request: Request):
        response = JSONResponse({"ok": True})
        auth.logout(request, response=response)
        return response

    with TestClient(app) as client:
        resp = client.post("/logout")
        assert resp.status_code == 200
        assert resp.json() == {"ok": True}
        assert "session_id=" in resp.headers["set-cookie"]
        assert "Max-Age=0" in resp.headers["set-cookie"]


def test_logout_custom_cookie_name(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth = _make_auth(
        secondary_storage,
        accounts_storage,
        session_storage,
        config={"session": {"cookies": {"name": "my_sid"}}},
    )
    app = FastAPI()

    session_id, _ = create_session("test", session_storage)

    @app.post("/logout")
    def do_logout(request: Request):
        response = JSONResponse({"ok": True})
        auth.logout(request, response=response)
        return response

    with TestClient(app) as client:
        client.cookies.set("my_sid", session_id)
        resp = client.post("/logout")
        assert resp.status_code == 200
        assert resp.json() == {"ok": True}
        assert "my_sid=" in resp.headers["set-cookie"]
        assert "Max-Age=0" in resp.headers["set-cookie"]

    # Session should be deleted
    assert get_session(session_id, session_storage) is None


# --- Shared setup between CrossAuth and AuthRouter ---


def _route_table(router: AuthRouter) -> list[tuple[str, list[str], str | None]]:
    return [
        (route.path, sorted(route.methods), route.operation_id)
        for route in router.routes
        if isinstance(route, APIRoute)
    ]


def _openapi(router: AuthRouter) -> dict:
    app = FastAPI()
    app.include_router(router)
    return app.openapi()


def test_cross_auth_and_router_share_one_setup(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    def lower(email: str) -> str:
        return email.lower()

    config: Config = {"session": {"max_age": 60}}
    auth = _make_auth(
        secondary_storage,
        accounts_storage,
        session_storage,
        config=config,
        normalize_email=lower,
    )
    context = auth.router.context

    assert context.secondary_storage is secondary_storage
    assert context.accounts_storage is accounts_storage
    assert context.session_storage is session_storage
    assert context.session_config is config["session"]
    assert context.normalize_email is lower
    assert auth.router.issuer is auth._setup.issuer
    assert context is auth._setup.context

    seen: list[object] = []

    @auth.after("login")
    def after_login(event) -> None:
        seen.append(event)

    payload = object()
    context.hooks.run_after("login", payload)
    assert seen == [payload]


@pytest.mark.parametrize("replace_resolver", [False, True])
def test_custom_user_resolver_reaches_router_and_facade(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
    replace_resolver: bool,
):
    user = accounts_storage.find_user_by_id("test")
    calls: list[str | None] = []

    def resolver(request) -> User | None:
        calls.append(request.headers.get("x-user"))
        return user if request.headers.get("x-user") == "test" else None

    auth = CrossAuth(
        providers=[GitHubProvider(client_id="id", client_secret="secret")],
        storage=secondary_storage,
        accounts_storage=accounts_storage,
        session_storage=session_storage,
        get_user_from_request=None if replace_resolver else resolver,
    )
    if replace_resolver:
        auth.router.context.get_user_from_request = resolver
    assert auth.router.context.get_user_from_request is resolver
    token, _ = auth.issue_session_token("test")

    app = FastAPI()
    app.include_router(auth.router)

    @app.get("/me")
    def me(request: Request):
        current = auth.get_current_user(request)
        return {"user": current.id if current else None}

    with TestClient(app, follow_redirects=False) as client:
        # A valid session must not bypass the custom resolver's denial policy.
        client.headers["Authorization"] = f"Bearer {token}"
        assert client.get("/me", headers={"x-user": "test"}).json() == {"user": "test"}
        assert client.get("/me").json() == {"user": None}
        assert (
            client.get("/github/connect", headers={"x-user": "test"}).status_code == 302
        )
        assert client.get("/github/connect").status_code == 401
        assert calls == ["test", None, "test", None]

        # Switching back to the built-in resolver restores session-based login.
        auth.router.context.get_user_from_request = auth._default_get_user_from_request
        assert client.get("/me").json() == {"user": "test"}
        assert calls == ["test", None, "test", None]


@pytest.mark.parametrize("cookie_auth", [False, True])
def test_direct_router_matches_cross_auth_router(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
    cookie_auth: bool,
):
    config: Config = {"session": {"cookies": {"auth": cookie_auth}}}
    providers: list[OAuth2Provider] = [
        GitHubProvider(client_id="id", client_secret="secret")
    ]
    direct = AuthRouter(
        providers=providers,
        secondary_storage=secondary_storage,
        accounts_storage=accounts_storage,
        session_storage=session_storage,
        get_user_from_request=lambda _: None,
        config=config,
        oauth_server=OAuthServer(),
    )
    facade = CrossAuth(
        providers=providers,
        storage=secondary_storage,
        accounts_storage=accounts_storage,
        session_storage=session_storage,
        config=config,
        oauth_server=OAuthServer(),
    ).router

    assert type(facade) is AuthRouter
    assert _route_table(facade) == _route_table(direct)
    routes = {
        (path, method)
        for path, methods, _ in _route_table(direct)
        for method in methods
    }
    assert {
        ("/github/connect", "GET"),
        ("/github/social-accounts", "DELETE"),
        ("/github/social-accounts/{social_account_id}", "DELETE"),
        ("/github/authorize", "GET"),
        ("/github/callback", "GET"),
        ("/github/callback", "POST"),
        ("/github/link", "POST"),
        ("/github/finalize-link", "POST"),
        ("/token", "POST"),
    } <= routes
    assert (("/github/login", "GET") in routes) is cookie_auth
    assert _openapi(facade) == _openapi(direct)
    assert facade.extra_schemas == direct.extra_schemas
