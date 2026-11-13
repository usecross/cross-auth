"""``CrossAuth.change_password`` changes the signed-in user's password.

It checks the current password, stores the new one through the accounts
storage, and revokes the user's other sessions through the ``session.revoke``
hooks while the session that changed it stays signed in.
"""

from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

import bcrypt
import pytest
import time_machine
from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from pydantic import BaseModel

from cross_auth import CommitCallback, SecondaryStorage, User
from cross_auth._password import hash_password
from cross_auth._session import create_session
from cross_auth.exceptions import CrossAuthException
from cross_auth.fastapi import CrossAuth, SessionCookieMiddleware
from cross_auth.hooks import AfterSessionRevokeEvent, BeforeSessionRevokeEvent

from ..conftest import TEST_PASSWORD, MemoryAccountsStorage, MemorySessionStorage
from ..conftest import User as MemoryUser

NEW_PASSWORD = "a new password"
NOW = datetime(2026, 11, 13, 12, 0, tzinfo=UTC)


class PasswordChange(BaseModel):
    current_password: str | None = TEST_PASSWORD
    new_password: str = NEW_PASSWORD
    revoke_other_sessions: bool = True


class PasswordAccountsStorage(MemoryAccountsStorage):
    """The memory accounts storage, able to store new passwords."""

    def set_password(self, user_id: Any, password: str) -> MemoryUser | None:
        user = self.find_user_by_id(user_id)
        if user is None:
            return None
        user.hashed_password = hash_password(password)
        return user


class DeferredPasswordAccountsStorage(PasswordAccountsStorage):
    """Defers commit callbacks, as a storage in an application transaction does."""

    def on_commit(self, callback: CommitCallback) -> None:
        pass


def _auth(
    secondary_storage: SecondaryStorage,
    accounts_storage: MemoryAccountsStorage,
    session_storage: MemorySessionStorage,
    **kwargs: Any,
) -> CrossAuth:
    kwargs.setdefault("config", {"session": {"cookies": {"secure": False}}})
    return CrossAuth(
        providers=[],
        storage=secondary_storage,
        accounts_storage=accounts_storage,
        session_storage=session_storage,
        **kwargs,
    )


def _app(auth: CrossAuth) -> FastAPI:
    app = FastAPI()
    app.add_middleware(SessionCookieMiddleware)

    @app.exception_handler(CrossAuthException)
    def cross_auth_error(request: Request, exc: CrossAuthException) -> JSONResponse:
        return JSONResponse({"error": exc.error}, status_code=exc.status_code)

    @app.post("/change-password")
    def change_password(request: Request, body: PasswordChange):
        user = auth.change_password(
            request,
            current_password=body.current_password,
            new_password=body.new_password,
            revoke_other_sessions=body.revoke_other_sessions,
        )
        return {"user": user.id}

    @app.get("/me")
    def me(user: Annotated[User | None, Depends(auth.get_current_user)]):
        return {"user": None if user is None else user.id}

    return app


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _change(client: TestClient, token: str, **body: Any):
    return client.post("/change-password", headers=_bearer(token), json=body)


@pytest.fixture(autouse=True)
def cheap_hashes(monkeypatch: pytest.MonkeyPatch) -> None:
    # Every change hashes a password; the default bcrypt cost is slow for tests.
    gensalt = bcrypt.gensalt
    monkeypatch.setattr(bcrypt, "gensalt", lambda: gensalt(rounds=4))


@pytest.fixture
def accounts_storage(test_password_hash: str) -> PasswordAccountsStorage:
    return PasswordAccountsStorage(test_password_hash)


@pytest.fixture
def auth(secondary_storage, accounts_storage, session_storage) -> CrossAuth:
    return _auth(secondary_storage, accounts_storage, session_storage)


@pytest.fixture
def client(auth: CrossAuth) -> TestClient:
    return TestClient(_app(auth))


@pytest.fixture
def test_user(accounts_storage: MemoryAccountsStorage) -> MemoryUser:
    return accounts_storage.data["test"]


@pytest.fixture
def social_user(accounts_storage: MemoryAccountsStorage) -> MemoryUser:
    """A user who signed up with a provider and has no password."""
    user = MemoryUser(
        id="social",
        email="social@example.com",
        email_verified=True,
        hashed_password=None,
        social_accounts=[],
    )
    accounts_storage.data["social"] = user
    return user


def test_change_password_stores_the_new_password(
    auth, client, test_user, session_storage
):
    token, _ = create_session(str(test_user.id), session_storage)

    response = _change(client, token)

    assert response.json() == {"user": "test"}
    assert auth.authenticate("test@example.com", NEW_PASSWORD) is test_user
    assert auth.authenticate("test@example.com", TEST_PASSWORD) is None


@pytest.mark.parametrize("transport", ["cookie", "bearer"])
def test_change_password_keeps_the_calling_session_and_revokes_the_others(
    client, test_user, social_user, session_storage, transport
):
    caller, caller_record = create_session("test", session_storage)
    _, other = create_session("test", session_storage)
    _, someone_elses = create_session("social", session_storage)
    headers = {}
    if transport == "cookie":
        client.cookies.set("session_id", caller)
    else:
        headers = _bearer(caller)

    response = client.post("/change-password", headers=headers, json={})

    assert response.status_code == 200
    assert client.get("/me", headers=headers).json() == {"user": "test"}
    assert caller_record.revoked_at is None
    assert other.revoked_at is not None
    assert someone_elses.revoked_at is None


def test_change_password_can_keep_the_other_sessions(client, session_storage):
    caller, _ = create_session("test", session_storage)
    _, other = create_session("test", session_storage)

    response = _change(client, caller, revoke_other_sessions=False)

    assert response.status_code == 200
    assert other.revoked_at is None


@pytest.mark.parametrize("current_password", ["wrong password", None])
def test_a_wrong_or_missing_current_password_changes_nothing(
    auth, client, test_user, session_storage, current_password
):
    revocations: list[BeforeSessionRevokeEvent] = []
    auth.before("session.revoke")(revocations.append)
    hashed_password = test_user.hashed_password
    caller, _ = create_session("test", session_storage)
    _, other = create_session("test", session_storage)

    response = _change(client, caller, current_password=current_password)

    assert (response.status_code, response.json()) == (
        400,
        {"error": "invalid_password"},
    )
    assert test_user.hashed_password == hashed_password
    assert other.revoked_at is None
    assert revocations == []


def test_a_user_without_a_password_sets_a_first_one(
    auth, client, social_user, session_storage
):
    caller, _ = create_session("social", session_storage)
    _, other = create_session("social", session_storage)

    response = _change(client, caller, current_password=None)

    assert response.json() == {"user": "social"}
    assert auth.authenticate("social@example.com", NEW_PASSWORD) is social_user
    # Setting a first password signs the other devices out, as a change does.
    assert other.revoked_at is not None


def test_a_user_without_a_password_cannot_send_a_current_password(
    client, social_user, session_storage
):
    caller, _ = create_session("social", session_storage)

    response = _change(client, caller, current_password="anything")

    assert response.status_code == 400
    assert response.json() == {"error": "invalid_password"}
    assert social_user.hashed_password is None


def test_change_password_needs_a_session(client, test_user):
    no_session = client.post("/change-password", json={})
    unknown = _change(client, "unknown-token")

    for response in (no_session, unknown):
        assert (response.status_code, response.json()) == (
            401,
            {"error": "unauthorized"},
        )


def test_a_refused_user_cannot_change_their_password(
    secondary_storage, accounts_storage, session_storage, test_user
):
    auth = _auth(
        secondary_storage,
        accounts_storage,
        session_storage,
        user_can_authenticate=lambda user: False,
    )
    hashed_password = test_user.hashed_password
    caller, _ = create_session("test", session_storage)

    response = _change(TestClient(_app(auth)), caller)

    assert response.status_code == 401
    assert test_user.hashed_password == hashed_password


def test_revoking_the_other_sessions_runs_the_session_revoke_hooks(
    auth, client, session_storage
):
    before: list[BeforeSessionRevokeEvent] = []
    after: list[AfterSessionRevokeEvent] = []
    auth.before("session.revoke")(before.append)
    auth.after("session.revoke")(after.append)
    caller, caller_record = create_session("test", session_storage)
    create_session("test", session_storage)
    create_session("test", session_storage)

    _change(client, caller)

    [before_event] = before
    assert (before_event.user_id, before_event.scope) == ("test", "others")
    assert before_event.keep_session_id == caller_record.id
    assert before_event.request is not None
    [after_event] = after
    assert (after_event.scope, after_event.revoked_count) == ("others", 2)


def test_a_session_revoke_hook_that_refuses_raises_after_the_change(
    auth, client, test_user, session_storage
):
    @auth.before("session.revoke")
    def refuse(event: BeforeSessionRevokeEvent) -> None:
        raise CrossAuthException("recent_sign_in_required", status_code=403)

    caller, _ = create_session("test", session_storage)
    _, other = create_session("test", session_storage)

    response = _change(client, caller)

    assert (response.status_code, response.json()) == (
        403,
        {"error": "recent_sign_in_required"},
    )
    # The password is stored before the sessions are revoked.
    assert auth.authenticate("test@example.com", NEW_PASSWORD) is test_user
    assert other.revoked_at is None


def test_a_password_longer_than_bcrypt_reads_changes_nothing(
    client, test_user, session_storage
):
    hashed_password = test_user.hashed_password
    caller, _ = create_session("test", session_storage)
    _, other = create_session("test", session_storage)

    # 37 two-byte characters: 74 bytes.
    response = _change(client, caller, new_password="é" * 37)

    assert (response.status_code, response.json()) == (
        400,
        {"error": "password_too_long"},
    )
    assert test_user.hashed_password == hashed_password
    assert other.revoked_at is None


def test_change_password_rolls_a_sliding_session_cookie(
    secondary_storage, accounts_storage, session_storage, test_user
):
    auth = _auth(
        secondary_storage,
        accounts_storage,
        session_storage,
        config={
            "session": {"max_age": 60, "update_age": 10, "cookies": {"secure": False}}
        },
    )
    client = TestClient(_app(auth))
    with time_machine.travel(NOW, tick=False):
        caller, _ = create_session("test", session_storage, max_age=60)
    client.cookies.set("session_id", caller)

    with time_machine.travel(NOW + timedelta(seconds=30), tick=False):
        response = client.post("/change-password", json={})

    assert response.status_code == 200
    assert f"session_id={caller}" in response.headers["set-cookie"]


def test_change_password_needs_an_accounts_storage_that_stores_passwords(
    secondary_storage, test_password_hash, session_storage
):
    auth = _auth(
        secondary_storage, MemoryAccountsStorage(test_password_hash), session_storage
    )
    caller, _ = create_session("test", session_storage)

    with pytest.raises(TypeError, match="has no set_password method"):
        _change(TestClient(_app(auth)), caller)


def test_revoking_needs_the_password_change_to_commit_first(
    secondary_storage, test_password_hash, session_storage
):
    accounts_storage = DeferredPasswordAccountsStorage(test_password_hash)
    user = accounts_storage.data["test"]
    hashed_password = user.hashed_password
    client = TestClient(
        _app(_auth(secondary_storage, accounts_storage, session_storage))
    )
    caller, _ = create_session("test", session_storage)
    _, other = create_session("test", session_storage)

    with pytest.raises(RuntimeError, match="uncommitted"):
        _change(client, caller)

    assert user.hashed_password == hashed_password
    assert other.revoked_at is None
    # Without revoking there is nothing to wait for.
    assert _change(client, caller, revoke_other_sessions=False).status_code == 200
    assert user.hashed_password != hashed_password
