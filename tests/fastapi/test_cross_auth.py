from typing import Annotated

from cross_web import AsyncHTTPRequest
from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from cross_auth import AccountsStorage, SecondaryStorage, User
from cross_auth._session import create_session, get_session
from cross_auth.fastapi import CrossAuth
from cross_auth.router import AuthRouter

TEST_PASSWORD = "password123"  # noqa: S105


def _make_auth(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    **kwargs,
) -> CrossAuth:
    return CrossAuth(
        providers=[],
        storage=secondary_storage,
        accounts_storage=accounts_storage,
        create_token=lambda _: ("", 0),
        trusted_origins=[],
        **kwargs,
    )


def test_get_current_user(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
):
    auth = _make_auth(secondary_storage, accounts_storage)
    app = FastAPI()
    app.include_router(auth.router)

    @app.get("/me")
    def me(user: Annotated[User | None, Depends(auth.get_current_user)]):
        if user is None:
            return {"user": None}
        return {"user": user.id}

    session_id, _ = create_session("test", secondary_storage)

    with TestClient(app) as client:
        resp = client.get("/me", cookies={"session_id": session_id})
        assert resp.status_code == 200
        assert resp.json() == {"user": "test"}


def test_get_current_user_no_cookie(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
):
    auth = _make_auth(secondary_storage, accounts_storage)
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
):
    auth = _make_auth(secondary_storage, accounts_storage)
    app = FastAPI()

    @app.get("/me")
    def me(user: Annotated[User, Depends(auth.require_current_user)]):
        return {"user": user.id}

    with TestClient(app) as client:
        resp = client.get("/me")
        assert resp.status_code == 401

    session_id, _ = create_session("test", secondary_storage)

    with TestClient(app) as client:
        resp = client.get("/me", cookies={"session_id": session_id})
        assert resp.status_code == 200
        assert resp.json() == {"user": "test"}


def test_get_current_user_custom_session_config(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
):
    auth = _make_auth(
        secondary_storage,
        accounts_storage,
        session_config={"cookie_name": "my_sid"},
    )
    app = FastAPI()

    @app.get("/me")
    def me(user: Annotated[User | None, Depends(auth.get_current_user)]):
        if user is None:
            return {"user": None}
        return {"user": user.id}

    session_id, _ = create_session("test", secondary_storage)

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
):
    auth = _make_auth(secondary_storage, accounts_storage)
    assert isinstance(auth.router, AuthRouter)

    app = FastAPI()
    app.include_router(auth.router)


def test_auto_wired_get_user_from_request(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
):
    """Verify that when no get_user_from_request is provided, the router's
    context uses session-based lookup. We expose the context's callback
    through an endpoint that calls it directly."""
    auth = _make_auth(secondary_storage, accounts_storage)

    session_id, _ = create_session("test", secondary_storage)

    app = FastAPI()
    app.include_router(auth.router)

    @app.get("/check")
    async def check(request: Request):
        async_request = AsyncHTTPRequest.from_fastapi(request)
        user = auth.router._get_user_from_request(async_request)
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
):
    auth = _make_auth(secondary_storage, accounts_storage)
    user = auth.authenticate("test@example.com", TEST_PASSWORD)
    assert user is not None
    assert user.email == "test@example.com"


def test_authenticate_wrong_password(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
):
    auth = _make_auth(secondary_storage, accounts_storage)
    result = auth.authenticate("test@example.com", "wrong-password")
    assert result is None


def test_login(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
):
    auth = _make_auth(secondary_storage, accounts_storage)
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


def test_login_custom_session_config(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
):
    auth = _make_auth(
        secondary_storage,
        accounts_storage,
        session_config={"cookie_name": "my_sid", "max_age": 3600},
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
):
    auth = _make_auth(secondary_storage, accounts_storage)
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
    session = get_session(session_id, secondary_storage)
    assert session is not None
    assert session.user_id == "test"


def test_logout(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
):
    auth = _make_auth(secondary_storage, accounts_storage)
    app = FastAPI()
    app.include_router(auth.router)

    # Create a session first.
    session_id, _ = create_session("test", secondary_storage)

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
    assert get_session(session_id, secondary_storage) is None


def test_logout_no_session_cookie(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
):
    auth = _make_auth(secondary_storage, accounts_storage)
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
):
    auth = _make_auth(
        secondary_storage,
        accounts_storage,
        session_config={"cookie_name": "my_sid"},
    )
    app = FastAPI()

    session_id, _ = create_session("test", secondary_storage)

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
    assert get_session(session_id, secondary_storage) is None
