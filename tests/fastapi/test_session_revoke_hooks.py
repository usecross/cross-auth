from dataclasses import dataclass, field
from typing import Any, cast

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from cross_auth import AccountsStorage, SecondaryStorage, SessionStorage
from cross_auth._session import create_session, get_session
from cross_auth.exceptions import CrossAuthException
from cross_auth.fastapi import CrossAuth
from cross_auth.hooks import AfterSessionRevokeEvent, BeforeSessionRevokeEvent


@dataclass
class Recorded:
    before: list[BeforeSessionRevokeEvent] = field(default_factory=list)
    after: list[AfterSessionRevokeEvent] = field(default_factory=list)


def _make_auth(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
) -> tuple[CrossAuth, Recorded]:
    auth = CrossAuth(
        providers=[],
        storage=secondary_storage,
        accounts_storage=accounts_storage,
        session_storage=session_storage,
    )
    recorded = Recorded()

    @auth.before("session.revoke")
    def record_before(event: BeforeSessionRevokeEvent) -> None:
        recorded.before.append(event)

    @auth.after("session.revoke")
    def record_after(event: AfterSessionRevokeEvent) -> None:
        recorded.after.append(event)

    return auth, recorded


def _client(auth: CrossAuth) -> TestClient:
    app = FastAPI()
    app.include_router(auth.router, prefix="/api/v1")
    return TestClient(app)


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_revoking_one_session_runs_the_hooks(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth, recorded = _make_auth(secondary_storage, accounts_storage, session_storage)
    caller_token, _ = create_session("test", session_storage)
    _, other = create_session("test", session_storage)

    with _client(auth) as client:
        response = client.delete(
            f"/api/v1/sessions/{other.id}", headers=_bearer(caller_token)
        )

    assert response.status_code == 204
    [before] = recorded.before
    assert (before.user_id, before.scope, before.keep_session_id) == (
        "test",
        "one",
        None,
    )
    assert before.session_record is not None
    assert before.session_record.id == other.id
    assert before.request is not None
    [after] = recorded.after
    assert (after.scope, after.revoked_count) == ("one", 1)
    assert after.request is before.request


def test_revoking_other_sessions_runs_the_hooks(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth, recorded = _make_auth(secondary_storage, accounts_storage, session_storage)
    caller_token, current = create_session("test", session_storage)
    create_session("test", session_storage)
    create_session("test", session_storage)
    create_session("test", session_storage, max_age=-1)

    with _client(auth) as client:
        response = client.post(
            "/api/v1/sessions/revoke-others", headers=_bearer(caller_token)
        )

    assert response.json() == {"revoked": 2}
    [before] = recorded.before
    assert (before.scope, before.keep_session_id, before.session_record) == (
        "others",
        current.id,
        None,
    )
    [after] = recorded.after
    assert (after.scope, after.keep_session_id, after.revoked_count) == (
        "others",
        current.id,
        2,
    )


@pytest.mark.parametrize("target", ["other", "current", "others"])
def test_a_before_hook_can_deny_the_revocation(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
    target: str,
):
    auth, recorded = _make_auth(secondary_storage, accounts_storage, session_storage)

    @auth.before("session.revoke")
    def deny(event: BeforeSessionRevokeEvent) -> None:
        raise CrossAuthException(
            "revocation_denied", "Sessions are locked", status_code=403
        )

    cookie_token, current = create_session("test", session_storage)
    other_token, other = create_session("test", session_storage)

    with _client(auth) as client:
        client.cookies.set("session_id", cookie_token)
        if target == "others":
            response = client.post("/api/v1/sessions/revoke-others")
        else:
            session_id = current.id if target == "current" else other.id
            response = client.delete(f"/api/v1/sessions/{session_id}")

    assert response.status_code == 403
    assert response.json() == {
        "error": "revocation_denied",
        "error_description": "Sessions are locked",
    }
    assert "set-cookie" not in response.headers
    assert get_session(cookie_token, session_storage) is not None
    assert get_session(other_token, session_storage) is not None
    assert len(recorded.before) == 1
    assert recorded.after == []


def test_crossauth_methods_run_the_hooks_without_a_request(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth, recorded = _make_auth(secondary_storage, accounts_storage, session_storage)
    _, first = create_session("test", session_storage)
    _, second = create_session("test", session_storage)
    create_session("test", session_storage)
    create_session("test", session_storage)

    assert auth.revoke_session(first.id, user_id="test") is True
    assert auth.revoke_other_sessions(user_id="test", keep_session_id=second.id) == 2
    assert auth.revoke_all_sessions(user_id="test") == 1

    assert [
        (event.scope, event.keep_session_id, event.request) for event in recorded.before
    ] == [("one", None, None), ("others", second.id, None), ("all", None, None)]
    assert [event.revoked_count for event in recorded.after] == [1, 2, 1]


def test_after_hooks_run_only_when_a_session_was_revoked(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth, recorded = _make_auth(secondary_storage, accounts_storage, session_storage)
    _, expired = create_session("test", session_storage, max_age=-1)
    _, only = create_session("test", session_storage)

    assert auth.revoke_session(expired.id, user_id="test") is False
    assert auth.revoke_other_sessions(user_id="test", keep_session_id=only.id) == 0

    # The before hooks still ran: they are the policy check for the request.
    assert [event.scope for event in recorded.before] == ["one", "others"]
    assert recorded.after == []
    stored = session_storage.get_any(expired.id)
    assert stored is not None
    assert stored.revoked_at is None


def test_another_users_session_runs_no_hooks(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth, recorded = _make_auth(secondary_storage, accounts_storage, session_storage)
    _, foreign = create_session("other", session_storage)

    auth.revoke_session(foreign.id, user_id="test")

    assert recorded.before == recorded.after == []


def test_before_hooks_cannot_return_an_event(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth, _ = _make_auth(secondary_storage, accounts_storage, session_storage)
    session_token, _ = create_session("test", session_storage)

    def rewrite(event: BeforeSessionRevokeEvent) -> BeforeSessionRevokeEvent:
        return event

    # The typed decorator rejects this handler; register it the way an
    # untyped caller would.
    auth.before("session.revoke")(cast(Any, rewrite))

    with pytest.raises(TypeError, match="session.revoke before hooks must return None"):
        auth.revoke_all_sessions(user_id="test")

    assert get_session(session_token, session_storage) is not None


def test_logout_runs_only_the_logout_hooks(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth, recorded = _make_auth(secondary_storage, accounts_storage, session_storage)
    session_token, _ = create_session("test", session_storage)

    with _client(auth) as client:
        response = client.post(
            "/api/v1/logout", json={"scope": "all"}, headers=_bearer(session_token)
        )

    assert response.status_code == 204
    assert get_session(session_token, session_storage) is None
    assert recorded.before == recorded.after == []


def test_a_before_hook_cannot_redirect_the_revocation(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    auth, recorded = _make_auth(secondary_storage, accounts_storage, session_storage)
    target_token, target = create_session("test", session_storage)
    other_token, other = create_session("test", session_storage)

    @auth.before("session.revoke")
    def redirect(event: BeforeSessionRevokeEvent) -> None:
        # A misbehaving hook rewrites the live record in place.
        cast(Any, event.session_record).id = other.id

    assert auth.revoke_session(target.id, user_id="test") is True

    assert get_session(target_token, session_storage) is None
    assert get_session(other_token, session_storage) is not None
