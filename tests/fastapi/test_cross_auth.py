from typing import Annotated

import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from cross_auth import AccountsStorage, SecondaryStorage, SessionStorage, User
from cross_auth._session import create_session, get_session
from cross_auth.fastapi import CrossAuth
from cross_auth.router import AuthRouter

TEST_PASSWORD = "password123"  # noqa: S105


def test_token_only_mode_without_session_storage(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
):
    auth = CrossAuth(
        providers=[],
        storage=secondary_storage,
        accounts_storage=accounts_storage,
        trusted_origins=[],
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
        token_issuer=issue_token,
        trusted_origins=[],
    )
    app = FastAPI()
    app.include_router(auth.router)

    with TestClient(app) as client:
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
        trusted_origins=[],
    )
    request = Request({"type": "http", "method": "GET", "path": "/", "headers": []})
    with pytest.raises(RuntimeError, match="session_storage is required"):
        auth.get_current_session(request)


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
        trusted_origins=[],
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
