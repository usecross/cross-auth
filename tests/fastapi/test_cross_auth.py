from typing import Annotated

from cross_web import AsyncHTTPRequest
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient

from cross_auth import (
    AccountsStorage,
    HookRegistration,
    HookRegistry,
    SecondaryStorage,
    User,
)
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
    cookie = auth.login("test")

    assert cookie.name == "session_id"
    assert cookie.value  # non-empty session id
    assert cookie.httponly is True
    assert cookie.secure is True
    assert cookie.samesite == "lax"
    assert cookie.path == "/"


def test_login_custom_session_config(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
):
    auth = _make_auth(
        secondary_storage,
        accounts_storage,
        session_config={"cookie_name": "my_sid", "max_age": 3600},
    )
    cookie = auth.login("test")

    assert cookie.name == "my_sid"
    assert cookie.value
    assert cookie.max_age == 3600


def test_login_creates_valid_session(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
):
    auth = _make_auth(secondary_storage, accounts_storage)
    cookie = auth.login("test")

    # The session should be retrievable
    session = get_session(cookie.value, secondary_storage)
    assert session is not None
    assert session.user_id == "test"


def test_logout(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
):
    auth = _make_auth(secondary_storage, accounts_storage)
    app = FastAPI()
    app.include_router(auth.router)

    # Create a session first
    login_cookie = auth.login("test")
    session_id = login_cookie.value

    @app.post("/do-logout")
    def do_logout(request: Request):
        cookie = auth.logout(request)
        return {"cookie_name": cookie.name, "cookie_value": cookie.value}

    with TestClient(app) as client:
        client.cookies.set("session_id", session_id)
        resp = client.post("/do-logout")
        assert resp.status_code == 200
        data = resp.json()
        assert data["cookie_name"] == "session_id"
        assert data["cookie_value"] == ""

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
        cookie = auth.logout(request)
        return {"cookie_name": cookie.name, "cookie_value": cookie.value}

    with TestClient(app) as client:
        resp = client.post("/logout")
        assert resp.status_code == 200
        data = resp.json()
        assert data["cookie_name"] == "session_id"
        assert data["cookie_value"] == ""


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

    login_cookie = auth.login("test")
    session_id = login_cookie.value

    @app.post("/logout")
    def do_logout(request: Request):
        cookie = auth.logout(request)
        return {
            "cookie_name": cookie.name,
            "cookie_value": cookie.value,
            "max_age": cookie.max_age,
        }

    with TestClient(app) as client:
        client.cookies.set("my_sid", session_id)
        resp = client.post("/logout")
        assert resp.status_code == 200
        data = resp.json()
        assert data["cookie_name"] == "my_sid"
        assert data["cookie_value"] == ""
        assert data["max_age"] == 0

    # Session should be deleted
    assert get_session(session_id, secondary_storage) is None


def test_accepts_hooks_mapping_configuration(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
):
    def after_user_info_hook(*, user_info, access_token, provider):
        return None

    auth = _make_auth(
        secondary_storage,
        accounts_storage,
        hooks={
            "after_user_info": [
                HookRegistration(callback=after_user_info_hook, priority=5),
            ]
        },
        hook_settings={"mode_by_event": {"after_user_info": "robust"}},
    )

    assert isinstance(auth.router, AuthRouter)


def test_accepts_hook_registry_configuration(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
):
    def after_user_info_hook(*, user_info, access_token, provider):
        return None

    registry = HookRegistry(
        hooks={"after_user_info": [after_user_info_hook]},
        settings={"mode_by_event": {"after_user_info": "robust"}},
    )

    auth = _make_auth(
        secondary_storage,
        accounts_storage,
        hooks=registry,
    )

    assert isinstance(auth.router, AuthRouter)
