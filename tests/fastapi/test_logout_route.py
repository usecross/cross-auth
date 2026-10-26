from dataclasses import replace
from typing import Annotated

from fastapi import Depends, FastAPI, Request, Response
from fastapi.testclient import TestClient

from cross_auth import AccountsStorage, SecondaryStorage, SessionStorage, User
from cross_auth._session import create_session, get_session
from cross_auth.exceptions import CrossAuthException
from cross_auth.fastapi import CrossAuth
from cross_auth.hooks import AfterLogoutEvent, BeforeLogoutEvent


def _make_auth(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
) -> CrossAuth:
    return CrossAuth(
        providers=[],
        storage=secondary_storage,
        accounts_storage=accounts_storage,
        session_storage=session_storage,
    )


def _make_app(auth: CrossAuth) -> FastAPI:
    app = FastAPI()
    app.include_router(auth.router, prefix="/api/v1")

    @app.get("/me")
    def me(user: Annotated[User | None, Depends(auth.get_current_user)]):
        return {"user_id": None if user is None else user.id}

    return app


def _assert_clears_cookie(response, name: str = "session_id") -> None:
    set_cookie = response.headers["set-cookie"]
    assert set_cookie.startswith(f"{name}=")
    assert "Max-Age=0" in set_cookie


def test_logout_route_revokes_cookie_session(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth = _make_auth(secondary_storage, accounts_storage, session_storage)
    session_token, _ = create_session("test", session_storage)

    with TestClient(_make_app(auth)) as client:
        client.cookies.set("session_id", session_token)
        response = client.post("/api/v1/logout")

    assert response.status_code == 204
    assert response.content == b""
    _assert_clears_cookie(response)
    assert get_session(session_token, session_storage) is None


def test_logout_route_revokes_bearer_session(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth = _make_auth(secondary_storage, accounts_storage, session_storage)
    session_token, _ = auth.issue_session_token("test")
    headers = {"Authorization": f"Bearer {session_token}"}

    with TestClient(_make_app(auth)) as client:
        assert client.get("/me", headers=headers).json() == {"user_id": "test"}

        response = client.post("/api/v1/logout", headers=headers)

        assert response.status_code == 204
        assert client.get("/me", headers=headers).json() == {"user_id": None}

    assert get_session(session_token, session_storage) is None


def test_logout_route_prefers_valid_bearer_over_stale_cookie(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth = _make_auth(secondary_storage, accounts_storage, session_storage)
    session_token, _ = auth.issue_session_token("test")

    with TestClient(_make_app(auth)) as client:
        client.cookies.set("session_id", "stale")
        response = client.post(
            "/api/v1/logout", headers={"Authorization": f"Bearer {session_token}"}
        )

    assert response.status_code == 204
    assert get_session(session_token, session_storage) is None


def test_logout_route_without_token(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth = _make_auth(secondary_storage, accounts_storage, session_storage)
    other_token, _ = create_session("test", session_storage)
    seen: list[AfterLogoutEvent] = []

    @auth.after("logout")
    def capture(event: AfterLogoutEvent) -> None:
        seen.append(event)

    with TestClient(_make_app(auth)) as client:
        response = client.post("/api/v1/logout")

    assert response.status_code == 204
    _assert_clears_cookie(response)
    assert [event.session_record for event in seen] == [None]
    assert get_session(other_token, session_storage) is not None


def test_logout_route_with_unknown_token(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth = _make_auth(secondary_storage, accounts_storage, session_storage)

    with TestClient(_make_app(auth)) as client:
        response = client.post(
            "/api/v1/logout", headers={"Authorization": "Bearer unknown"}
        )

    assert response.status_code == 204


def test_logout_route_with_revoked_token(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth = _make_auth(secondary_storage, accounts_storage, session_storage)
    session_token, _ = auth.issue_session_token("test")
    headers = {"Authorization": f"Bearer {session_token}"}

    with TestClient(_make_app(auth)) as client:
        first = client.post("/api/v1/logout", headers=headers)
        second = client.post("/api/v1/logout", headers=headers)

    assert first.status_code == 204
    assert second.status_code == 204


def test_logout_route_with_expired_token(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth = _make_auth(secondary_storage, accounts_storage, session_storage)
    session_token, _ = create_session("test", session_storage, max_age=-1)

    with TestClient(_make_app(auth)) as client:
        client.cookies.set("session_id", session_token)
        response = client.post("/api/v1/logout")

    assert response.status_code == 204


def test_logout_before_hook_sets_session_token(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth = _make_auth(secondary_storage, accounts_storage, session_storage)
    session_token, session_record = auth.issue_session_token("test")
    seen: list[AfterLogoutEvent] = []

    @auth.before("logout")
    def token_from_header(event: BeforeLogoutEvent) -> BeforeLogoutEvent:
        assert event.session_token is None
        assert event.session_record is None
        return replace(event, session_token=event.request.headers["x-session-token"])

    @auth.after("logout")
    def capture(event: AfterLogoutEvent) -> None:
        seen.append(event)

    with TestClient(_make_app(auth)) as client:
        response = client.post(
            "/api/v1/logout", headers={"X-Session-Token": session_token}
        )

    assert response.status_code == 204
    assert get_session(session_token, session_storage) is None
    assert [event.session_record for event in seen] == [session_record]


def test_logout_before_hook_session_record_wins_over_token(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth = _make_auth(secondary_storage, accounts_storage, session_storage)
    request_token, _ = auth.issue_session_token("test")
    chosen_token, chosen_record = auth.issue_session_token("test")

    @auth.before("logout")
    def pick_record(event: BeforeLogoutEvent) -> BeforeLogoutEvent:
        return replace(event, session_token=None, session_record=chosen_record)

    with TestClient(_make_app(auth)) as client:
        response = client.post(
            "/api/v1/logout", headers={"Authorization": f"Bearer {request_token}"}
        )

    assert response.status_code == 204
    assert get_session(chosen_token, session_storage) is None
    assert get_session(request_token, session_storage) is not None


def test_logout_route_reports_before_hook_errors(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth = _make_auth(secondary_storage, accounts_storage, session_storage)
    session_token, _ = auth.issue_session_token("test")

    @auth.before("logout")
    def refuse(event: BeforeLogoutEvent) -> None:
        raise CrossAuthException("logout_blocked", "Not now", 403)

    with TestClient(_make_app(auth)) as client:
        response = client.post(
            "/api/v1/logout", headers={"Authorization": f"Bearer {session_token}"}
        )

    assert response.status_code == 403
    assert response.json() == {
        "error": "logout_blocked",
        "error_description": "Not now",
    }
    assert get_session(session_token, session_storage) is not None


def test_logout_method_revokes_bearer_session(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth = _make_auth(secondary_storage, accounts_storage, session_storage)
    session_token, _ = auth.issue_session_token("test")
    app = FastAPI()

    @app.post("/sign-out")
    def sign_out(request: Request, response: Response) -> None:
        auth.logout(request, response=response)

    with TestClient(app) as client:
        response = client.post(
            "/sign-out", headers={"Authorization": f"Bearer {session_token}"}
        )

    assert response.status_code == 200
    assert get_session(session_token, session_storage) is None


def test_logout_route_scope_all_revokes_every_session_of_the_user(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth = _make_auth(secondary_storage, accounts_storage, session_storage)
    session_token, session_record = auth.issue_session_token("test")
    other_device_token, _ = create_session("test", session_storage)
    other_user_token, _ = create_session("other", session_storage)
    seen: list[AfterLogoutEvent] = []

    @auth.after("logout")
    def capture(event: AfterLogoutEvent) -> None:
        seen.append(event)

    with TestClient(_make_app(auth)) as client:
        response = client.post(
            "/api/v1/logout",
            headers={"Authorization": f"Bearer {session_token}"},
            json={"scope": "all"},
        )

    assert response.status_code == 204
    _assert_clears_cookie(response)
    assert get_session(session_token, session_storage) is None
    assert get_session(other_device_token, session_storage) is None
    assert get_session(other_user_token, session_storage) is not None
    assert [(e.scope, e.revoked_count, e.session_record) for e in seen] == [
        ("all", 2, session_record)
    ]


def test_logout_route_scope_all_without_token(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth = _make_auth(secondary_storage, accounts_storage, session_storage)
    other_token, _ = create_session("test", session_storage)

    with TestClient(_make_app(auth)) as client:
        response = client.post("/api/v1/logout", json={"scope": "all"})

    assert response.status_code == 204
    assert get_session(other_token, session_storage) is not None


def test_logout_route_defaults_to_current_scope(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth = _make_auth(secondary_storage, accounts_storage, session_storage)
    session_token, _ = auth.issue_session_token("test")
    other_device_token, _ = create_session("test", session_storage)
    seen: list[AfterLogoutEvent] = []

    @auth.after("logout")
    def capture(event: AfterLogoutEvent) -> None:
        seen.append(event)

    with TestClient(_make_app(auth)) as client:
        response = client.post(
            "/api/v1/logout",
            headers={"Authorization": f"Bearer {session_token}"},
            json={},
        )

    assert response.status_code == 204
    assert get_session(session_token, session_storage) is None
    assert get_session(other_device_token, session_storage) is not None
    assert [(e.scope, e.revoked_count) for e in seen] == [("current", 1)]


def test_logout_route_rejects_unknown_scope(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth = _make_auth(secondary_storage, accounts_storage, session_storage)
    session_token, _ = auth.issue_session_token("test")

    with TestClient(_make_app(auth)) as client:
        response = client.post(
            "/api/v1/logout",
            headers={"Authorization": f"Bearer {session_token}"},
            json={"scope": "others"},
        )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"
    assert get_session(session_token, session_storage) is not None


def test_logout_before_hook_changes_scope(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth = _make_auth(secondary_storage, accounts_storage, session_storage)
    session_token, _ = auth.issue_session_token("test")
    other_device_token, _ = create_session("test", session_storage)

    @auth.before("logout")
    def only_current(event: BeforeLogoutEvent) -> BeforeLogoutEvent:
        assert event.scope == "all"
        return replace(event, scope="current")

    with TestClient(_make_app(auth)) as client:
        response = client.post(
            "/api/v1/logout",
            headers={"Authorization": f"Bearer {session_token}"},
            json={"scope": "all"},
        )

    assert response.status_code == 204
    assert get_session(session_token, session_storage) is None
    assert get_session(other_device_token, session_storage) is not None


def test_logout_method_scope_all(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth = _make_auth(secondary_storage, accounts_storage, session_storage)
    session_token, _ = create_session("test", session_storage)
    other_device_token, _ = auth.issue_session_token("test")
    app = FastAPI()

    @app.post("/sign-out-everywhere")
    def sign_out_everywhere(request: Request, response: Response) -> None:
        auth.logout(request, response=response, scope="all")

    with TestClient(app) as client:
        client.cookies.set("session_id", session_token)
        response = client.post("/sign-out-everywhere")

    assert response.status_code == 200
    assert get_session(session_token, session_storage) is None
    assert get_session(other_device_token, session_storage) is None
