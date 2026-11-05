from datetime import datetime, timedelta, timezone

import pytest
import time_machine
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.testclient import TestClient
from sqlmodel import Session

from cross_auth import AccountsStorage, SecondaryStorage, SessionStorage
from cross_auth._session import create_session, get_session
from cross_auth._storage import SessionRecord
from cross_auth.fastapi import CrossAuth

from ..conftest import MemoryAccountsStorage
from ..conftest import User as MemoryUser
from ..storage.conftest import make_sqlite_engine
from ..storage.models import SessionStore

SESSION_FIELDS = {
    "id",
    "status",
    "client_id",
    "client_name",
    "user_agent",
    "ip",
    "login_method",
    "created_at",
    "last_active_at",
    "expires_at",
    "revoked_at",
    "current",
}


@pytest.fixture
def sqlite_session_storage() -> SessionStore:
    engine = make_sqlite_engine()
    return SessionStore(session_factory=lambda: Session(engine))


@pytest.fixture
def accounts_storage(accounts_storage: MemoryAccountsStorage) -> MemoryAccountsStorage:
    accounts_storage.data["other"] = MemoryUser(
        id="other",
        email="other@example.com",
        email_verified=True,
        hashed_password=None,
        social_accounts=[],
    )
    return accounts_storage


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


def _client(auth: CrossAuth) -> TestClient:
    app = FastAPI()
    app.include_router(auth.router, prefix="/api/v1")
    return TestClient(app)


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _session(
    session_storage: SessionStorage,
    user_id: str = "test",
    *,
    minutes_ago: int = 0,
    **kwargs,
) -> tuple[str, SessionRecord]:
    created_at = datetime.now(tz=timezone.utc) - timedelta(minutes=minutes_ago)
    with time_machine.travel(created_at, tick=False):
        return create_session(user_id, session_storage, **kwargs)


def test_list_marks_the_current_session_newest_first(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth = _make_auth(secondary_storage, accounts_storage, session_storage)
    _, oldest = _session(session_storage, minutes_ago=30)
    current_token, current = _session(session_storage, minutes_ago=20)
    _, newest = _session(session_storage, minutes_ago=10)

    with _client(auth) as client:
        response = client.get("/api/v1/sessions", headers=_bearer(current_token))

    assert response.status_code == 200
    body = response.json()
    assert body["next_cursor"] is None
    assert [(s["id"], s["current"]) for s in body["sessions"]] == [
        (newest.id, False),
        (current.id, True),
        (oldest.id, False),
    ]
    assert "set-cookie" not in response.headers


def test_list_describes_each_session_without_its_token(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth = _make_auth(secondary_storage, accounts_storage, session_storage)
    session_token, record = create_session(
        "test",
        session_storage,
        metadata={
            "client_id": "cli",
            "client_name": "Command line",
            "user_agent": "curl/8",
            "ip": "203.0.113.7",
        },
        login_method="github",
    )

    with _client(auth) as client:
        response = client.get("/api/v1/sessions", headers=_bearer(session_token))

    [session] = response.json()["sessions"]
    assert set(session) == SESSION_FIELDS
    assert record.last_active_at is not None
    assert session == {
        "id": record.id,
        "status": "active",
        "client_id": "cli",
        "client_name": "Command line",
        "user_agent": "curl/8",
        "ip": "203.0.113.7",
        "login_method": "github",
        "created_at": _iso(record.created_at),
        "last_active_at": _iso(record.last_active_at),
        "expires_at": _iso(record.expires_at),
        "revoked_at": None,
        "current": True,
    }


def test_list_shows_only_the_callers_active_sessions(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth = _make_auth(secondary_storage, accounts_storage, session_storage)
    session_token, current = create_session("test", session_storage)
    _, revoked = create_session("test", session_storage)
    session_storage.revoke(revoked.id, revoked_at=datetime.now(tz=timezone.utc))
    create_session("test", session_storage, max_age=-1)
    create_session("other", session_storage)

    with _client(auth) as client:
        response = client.get("/api/v1/sessions", headers=_bearer(session_token))

    assert [s["id"] for s in response.json()["sessions"]] == [current.id]


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (None, ["active"]),
        ("active", ["active"]),
        ("expired", ["expired"]),
        ("revoked", ["revoked"]),
        ("all", ["active", "revoked", "expired"]),
    ],
)
def test_list_filters_by_status(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
    status: str | None,
    expected: list[str],
):
    auth = _make_auth(secondary_storage, accounts_storage, session_storage)
    _session(session_storage, minutes_ago=3, max_age=60)  # expired
    _, revoked = _session(session_storage, minutes_ago=2)
    session_storage.revoke(revoked.id, revoked_at=datetime.now(tz=timezone.utc))
    session_token, _ = _session(session_storage, minutes_ago=1)

    with _client(auth) as client:
        response = client.get(
            "/api/v1/sessions",
            params={} if status is None else {"status": status},
            headers=_bearer(session_token),
        )

    sessions = response.json()["sessions"]
    assert [s["status"] for s in sessions] == expected
    revoked_at = {s["status"]: s["revoked_at"] for s in sessions}.get("revoked")
    if "revoked" in expected:
        assert revoked_at is not None


def test_list_marks_the_cookie_session_current(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth = _make_auth(secondary_storage, accounts_storage, session_storage)
    _, other = _session(session_storage, minutes_ago=1)
    cookie_token, current = create_session("test", session_storage)

    with _client(auth) as client:
        client.cookies.set("session_id", cookie_token)
        response = client.get("/api/v1/sessions")

    assert [(s["id"], s["current"]) for s in response.json()["sessions"]] == [
        (current.id, True),
        (other.id, False),
    ]


def test_list_prefers_the_cookie_session_over_a_bearer_token(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth = _make_auth(secondary_storage, accounts_storage, session_storage)
    cookie_token, cookie_session = create_session("other", session_storage)
    bearer_token, _ = create_session("test", session_storage)

    with _client(auth) as client:
        client.cookies.set("session_id", cookie_token)
        response = client.get("/api/v1/sessions", headers=_bearer(bearer_token))

    assert [(s["id"], s["current"]) for s in response.json()["sessions"]] == [
        (cookie_session.id, True)
    ]


@pytest.mark.parametrize(
    ("method", "path", "status_code"),
    [
        ("GET", "/api/v1/sessions", 200),
        ("GET", "/api/v1/sessions?limit=0", 400),
        ("DELETE", "/api/v1/sessions/does-not-exist", 404),
        ("POST", "/api/v1/sessions/revoke-others", 200),
    ],
)
def test_routes_roll_a_sliding_cookie_session(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
    method: str,
    path: str,
    status_code: int,
):
    # The lookup extends the stored session, so every answer, errors
    # included, re-sends the cookie with the new lifetime.
    auth = _make_auth(
        secondary_storage,
        accounts_storage,
        session_storage,
        config={"session": {"update_age": 60}},
    )
    cookie_token, _ = _session(session_storage, minutes_ago=5)

    with _client(auth) as client:
        client.cookies.set("session_id", cookie_token)
        response = client.request(method, path)

    assert response.status_code == status_code
    set_cookie = response.headers["set-cookie"]
    assert set_cookie.startswith(f"session_id={cookie_token};")
    assert "Max-Age=86400" in set_cookie


def test_list_pages_with_a_cursor(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    sqlite_session_storage: SessionStore,
):
    session_storage = sqlite_session_storage
    auth = _make_auth(secondary_storage, accounts_storage, session_storage)
    _, oldest = _session(session_storage, minutes_ago=3)
    _, middle = _session(session_storage, minutes_ago=2)
    session_token, newest = _session(session_storage, minutes_ago=1)

    with _client(auth) as client:
        first = client.get(
            "/api/v1/sessions", params={"limit": 2}, headers=_bearer(session_token)
        ).json()
        second = client.get(
            "/api/v1/sessions",
            params={"limit": 2, "cursor": first["next_cursor"]},
            headers=_bearer(session_token),
        ).json()

    assert [(s["id"], s["current"]) for s in first["sessions"]] == [
        (str(newest.id), True),
        (str(middle.id), False),
    ]
    assert first["next_cursor"] is not None
    assert [s["id"] for s in second["sessions"]] == [str(oldest.id)]
    assert second["next_cursor"] is None


@pytest.mark.parametrize(
    "params",
    [
        {"limit": "0"},
        {"limit": "101"},
        {"limit": "many"},
        {"cursor": "not-a-cursor"},
        {"status": "deleted"},
    ],
)
def test_list_rejects_an_invalid_page(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    sqlite_session_storage: SessionStore,
    params: dict[str, str],
):
    session_storage = sqlite_session_storage
    auth = _make_auth(secondary_storage, accounts_storage, session_storage)
    session_token, _ = create_session("test", session_storage)

    with _client(auth) as client:
        response = client.get(
            "/api/v1/sessions", params=params, headers=_bearer(session_token)
        )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"


def test_revoking_a_session_logs_out_its_token(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth = _make_auth(secondary_storage, accounts_storage, session_storage)
    caller_token, _ = create_session("test", session_storage)
    other_token, other = create_session("test", session_storage)

    with _client(auth) as client:
        response = client.delete(
            f"/api/v1/sessions/{other.id}", headers=_bearer(caller_token)
        )

        assert response.status_code == 204
        assert response.content == b""
        assert "set-cookie" not in response.headers
        revoked = client.get("/api/v1/sessions", headers=_bearer(other_token))
        assert revoked.status_code == 401
        assert (
            client.get("/api/v1/sessions", headers=_bearer(caller_token)).status_code
            == 200
        )


def test_revoking_another_users_session_is_not_found(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth = _make_auth(secondary_storage, accounts_storage, session_storage)
    caller_token, _ = create_session("test", session_storage)
    other_user_token, other_user_session = create_session("other", session_storage)

    with _client(auth) as client:
        foreign = client.delete(
            f"/api/v1/sessions/{other_user_session.id}", headers=_bearer(caller_token)
        )
        unknown = client.delete(
            "/api/v1/sessions/does-not-exist", headers=_bearer(caller_token)
        )

        assert foreign.status_code == 404
        # Indistinguishable from an id that does not exist.
        assert (
            foreign.json()
            == unknown.json()
            == {
                "error": "session_not_found",
                "error_description": "Session not found",
            }
        )
        assert (
            client.get(
                "/api/v1/sessions", headers=_bearer(other_user_token)
            ).status_code
            == 200
        )


def test_revoking_an_id_the_storage_cannot_parse_is_not_found(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    sqlite_session_storage: SessionStore,
):
    session_storage = sqlite_session_storage
    auth = _make_auth(secondary_storage, accounts_storage, session_storage)
    session_token, _ = create_session("test", session_storage)

    with _client(auth) as client:
        response = client.delete(
            "/api/v1/sessions/not-an-int", headers=_bearer(session_token)
        )

    assert response.status_code == 404


def test_revoking_the_current_bearer_session(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth = _make_auth(secondary_storage, accounts_storage, session_storage)
    session_token, record = create_session("test", session_storage)

    with _client(auth) as client:
        response = client.delete(
            f"/api/v1/sessions/{record.id}", headers=_bearer(session_token)
        )

    assert response.status_code == 204
    assert "set-cookie" not in response.headers
    assert get_session(session_token, session_storage) is None


def test_revoking_the_current_cookie_session_clears_the_cookie(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth = _make_auth(secondary_storage, accounts_storage, session_storage)
    cookie_token, record = create_session("test", session_storage)

    with _client(auth) as client:
        client.cookies.set("session_id", cookie_token)
        response = client.delete(f"/api/v1/sessions/{record.id}")

    assert response.status_code == 204
    set_cookie = response.headers["set-cookie"]
    assert set_cookie.startswith("session_id=")
    assert "Max-Age=0" in set_cookie
    assert get_session(cookie_token, session_storage) is None


def test_revoking_another_session_keeps_the_cookie(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth = _make_auth(secondary_storage, accounts_storage, session_storage)
    cookie_token, _ = create_session("test", session_storage)
    _, other = create_session("test", session_storage)

    with _client(auth) as client:
        client.cookies.set("session_id", cookie_token)
        response = client.delete(f"/api/v1/sessions/{other.id}")

    assert response.status_code == 204
    assert "set-cookie" not in response.headers
    assert get_session(cookie_token, session_storage) is not None


def test_revoking_an_expired_session_leaves_it_expired(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth = _make_auth(secondary_storage, accounts_storage, session_storage)
    session_token, _ = create_session("test", session_storage)
    _, expired = _session(session_storage, minutes_ago=2, max_age=60)

    with _client(auth) as client:
        response = client.delete(
            f"/api/v1/sessions/{expired.id}", headers=_bearer(session_token)
        )

    assert response.status_code == 204
    stored = session_storage.get_any(expired.id)
    assert stored is not None
    assert stored.revoked_at is None


def test_revoking_an_already_revoked_session(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth = _make_auth(secondary_storage, accounts_storage, session_storage)
    session_token, _ = create_session("test", session_storage)
    _, other = create_session("test", session_storage)

    with _client(auth) as client:
        first = client.delete(
            f"/api/v1/sessions/{other.id}", headers=_bearer(session_token)
        )
        second = client.delete(
            f"/api/v1/sessions/{other.id}", headers=_bearer(session_token)
        )

    assert (first.status_code, second.status_code) == (204, 204)


def test_revoke_others_keeps_the_current_session(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth = _make_auth(secondary_storage, accounts_storage, session_storage)
    current_token, _ = create_session("test", session_storage)
    first_token, _ = create_session("test", session_storage)
    second_token, _ = create_session("test", session_storage)
    other_user_token, _ = create_session("other", session_storage)

    with _client(auth) as client:
        response = client.post(
            "/api/v1/sessions/revoke-others", headers=_bearer(current_token)
        )

    assert response.status_code == 200
    assert response.json() == {"revoked": 2}
    assert get_session(current_token, session_storage) is not None
    assert get_session(first_token, session_storage) is None
    assert get_session(second_token, session_storage) is None
    assert get_session(other_user_token, session_storage) is not None


def test_revoke_others_counts_only_active_sessions(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth = _make_auth(secondary_storage, accounts_storage, session_storage)
    current_token, _ = create_session("test", session_storage)
    other_token, _ = create_session("test", session_storage)
    _, expired = _session(session_storage, minutes_ago=2, max_age=60)

    with _client(auth) as client:
        response = client.post(
            "/api/v1/sessions/revoke-others", headers=_bearer(current_token)
        )
        listed = client.get(
            "/api/v1/sessions",
            params={"status": "expired"},
            headers=_bearer(current_token),
        )

    assert response.json() == {"revoked": 1}
    assert get_session(other_token, session_storage) is None
    # The expired session was not revoked: it still reads as expired.
    assert [(s["id"], s["status"]) for s in listed.json()["sessions"]] == [
        (expired.id, "expired")
    ]


def test_revoke_others_keeps_the_current_cookie_session(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth = _make_auth(secondary_storage, accounts_storage, session_storage)
    cookie_token, _ = create_session("test", session_storage)
    other_token, _ = create_session("test", session_storage)

    with _client(auth) as client:
        client.cookies.set("session_id", cookie_token)
        response = client.post("/api/v1/sessions/revoke-others")

    assert response.json() == {"revoked": 1}
    assert "set-cookie" not in response.headers
    assert get_session(cookie_token, session_storage) is not None
    assert get_session(other_token, session_storage) is None


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/api/v1/sessions"),
        ("DELETE", "/api/v1/sessions/{session_id}"),
        ("POST", "/api/v1/sessions/revoke-others"),
    ],
)
@pytest.mark.parametrize("headers", [{}, _bearer("unknown")])
def test_requests_without_a_session_are_unauthorized(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
    method: str,
    path: str,
    headers: dict[str, str],
):
    # Like /logout, the routes need a session: a get_user_from_request that
    # accepts another credential does not authenticate them.
    auth = _make_auth(
        secondary_storage,
        accounts_storage,
        session_storage,
        get_user_from_request=lambda request: accounts_storage.find_user_by_id("test"),
    )
    session_token, record = create_session("test", session_storage)

    with _client(auth) as client:
        response = client.request(
            method, path.format(session_id=record.id), headers=headers
        )

    assert response.status_code == 401
    assert response.json()["error"] == "unauthorized"
    assert get_session(session_token, session_storage) is not None


BROWSER_ORIGIN = "https://app.example.com"


def test_csrf_dependency_guards_cookie_mutations(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    """Cross Auth leaves CSRF to the application, as for /logout. The
    dependency from the security guide covers the session routes."""
    auth = _make_auth(secondary_storage, accounts_storage, session_storage)

    def protect_auth_browser_requests(request: Request) -> None:
        if request.method in {"GET", "HEAD", "OPTIONS"}:
            return
        if request.headers.get("origin") != BROWSER_ORIGIN:
            raise HTTPException(403, "Untrusted browser request")

    app = FastAPI()
    app.include_router(
        auth.router,
        prefix="/api/v1",
        dependencies=[Depends(protect_auth_browser_requests)],
    )
    cookie_token, current = create_session("test", session_storage)
    other_token, other = create_session("test", session_storage)
    forged = {"Origin": "https://evil.example"}
    trusted = {"Origin": BROWSER_ORIGIN}

    with TestClient(app) as client:
        client.cookies.set("session_id", cookie_token)

        assert client.get("/api/v1/sessions").status_code == 200
        assert (
            client.delete(f"/api/v1/sessions/{other.id}", headers=forged).status_code
            == 403
        )
        assert (
            client.post("/api/v1/sessions/revoke-others", headers=forged).status_code
            == 403
        )
        assert get_session(other_token, session_storage) is not None

        assert (
            client.delete(f"/api/v1/sessions/{other.id}", headers=trusted).status_code
            == 204
        )
        assert get_session(other_token, session_storage) is None
        response = client.delete(f"/api/v1/sessions/{current.id}", headers=trusted)

    assert response.status_code == 204
    assert "Max-Age=0" in response.headers["set-cookie"]
    assert get_session(cookie_token, session_storage) is None


def test_routes_are_not_mounted_without_session_storage(
    secondary_storage: SecondaryStorage, accounts_storage: AccountsStorage
):
    auth = CrossAuth(
        providers=[], storage=secondary_storage, accounts_storage=accounts_storage
    )

    with _client(auth) as client:
        assert client.get("/api/v1/sessions").status_code == 404
