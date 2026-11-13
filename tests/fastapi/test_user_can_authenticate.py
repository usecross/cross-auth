"""``user_can_authenticate`` refuses a user at every login and session use.

Logins refuse with ``access_denied`` (or the rule's own ``CrossAuthException``)
before anything is issued. Session uses treat a refused user like an unknown
one, check the user before a sliding refresh, and never revoke the session.
"""

from datetime import UTC, datetime, timedelta
from typing import Annotated, Any
from unittest import mock

import pytest
import time_machine
from cross_web import HTTPRequest
from fastapi import Depends, FastAPI, Request, Response
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from cross_auth import OAuthServer, SecondaryStorage, User
from cross_auth._session import create_session
from cross_auth._tokens import TokenIssueRequest
from cross_auth.exceptions import CrossAuthException
from cross_auth.fastapi import CrossAuth, SessionCookieMiddleware
from cross_auth.hooks import AfterAuthenticateEvent, BeforeLoginEvent

from ..conftest import (
    LEGACY_PASSWORD_SERVER,
    TEST_CLIENTS,
    TEST_PASSWORD,
    MemoryAccountsStorage,
    MemorySessionStorage,
    legacy_password_grant,
)
from ..conftest import User as MemoryUser

NOW = datetime(2026, 11, 12, 12, 0, tzinfo=UTC)
SLIDING = {"max_age": 60, "update_age": 10, "cookies": {"secure": False}}
SUSPENDED = CrossAuthException("account_suspended", "Account suspended", 403)
REFUSED = ("access_denied", "Sign-in is not allowed", 403)


class Rule:
    """Refuses the user ids in ``refused`` and records each user it checks."""

    def __init__(self) -> None:
        self.refused: set[str] = set()
        self.error: CrossAuthException | None = None
        self.checked: list[str] = []

    def __call__(self, user: User) -> bool:
        self.checked.append(str(user.id))
        if str(user.id) not in self.refused:
            return True
        if self.error is not None:
            raise self.error
        return False


@pytest.fixture
def rule() -> Rule:
    return Rule()


def _auth(
    secondary_storage: SecondaryStorage,
    accounts_storage: MemoryAccountsStorage,
    session_storage: MemorySessionStorage,
    rule: Rule | None,
    **kwargs: Any,
) -> CrossAuth:
    return CrossAuth(
        providers=[],
        storage=secondary_storage,
        accounts_storage=accounts_storage,
        session_storage=session_storage,
        user_can_authenticate=rule,
        **kwargs,
    )


def _app(auth: CrossAuth) -> FastAPI:
    app = FastAPI()
    app.add_middleware(SessionCookieMiddleware)
    app.include_router(auth.router)

    @app.exception_handler(CrossAuthException)
    def cross_auth_error(request: Request, exc: CrossAuthException) -> JSONResponse:
        return JSONResponse(
            {"error": exc.error, "error_description": exc.error_description},
            status_code=exc.status_code,
        )

    @app.get("/me")
    def me(user: Annotated[User | None, Depends(auth.get_current_user)]):
        return {"user": None if user is None else user.id}

    @app.get("/protected")
    def protected(user: Annotated[User, Depends(auth.require_current_user)]):
        return {"user": user.id}

    return app


def _error(exc: CrossAuthException) -> tuple[str, str | None, int]:
    return exc.error, exc.error_description, exc.status_code


# Logins


def test_login_refuses_a_user_the_rule_refuses(
    secondary_storage, accounts_storage, session_storage, rule
):
    auth = _auth(secondary_storage, accounts_storage, session_storage, rule)
    before_login = mock.Mock(return_value=None)
    auth.before("login")(before_login)
    rule.refused.add("test")

    with pytest.raises(CrossAuthException) as exc:
        auth.login("test", response=Response())

    assert _error(exc.value) == REFUSED
    assert session_storage.records == {}
    before_login.assert_not_called()


def test_a_rule_raising_refuses_with_its_own_error(
    secondary_storage, accounts_storage, session_storage, rule
):
    auth = _auth(secondary_storage, accounts_storage, session_storage, rule)
    rule.refused.add("test")
    rule.error = SUSPENDED

    with pytest.raises(CrossAuthException) as login:
        auth.login("test", response=Response())
    with pytest.raises(CrossAuthException) as token:
        auth.issue_session_token("test")

    assert login.value is SUSPENDED
    assert token.value is SUSPENDED
    assert session_storage.records == {}


def test_issue_session_token_refuses_a_user_the_rule_refuses(
    secondary_storage, accounts_storage, session_storage, rule
):
    auth = _auth(secondary_storage, accounts_storage, session_storage, rule)
    rule.refused.add("test")

    with pytest.raises(CrossAuthException) as exc:
        auth.issue_session_token("test", login_method="passkey")

    assert _error(exc.value) == REFUSED
    assert session_storage.records == {}


def test_logins_for_an_allowed_user_go_ahead(
    secondary_storage, accounts_storage, session_storage, rule
):
    auth = _auth(secondary_storage, accounts_storage, session_storage, rule)

    auth.login("test", response=Response())
    auth.issue_session_token("test")

    assert len(session_storage.records) == 2
    assert rule.checked == ["test", "test"]


def test_a_rule_refuses_a_login_for_a_user_that_is_not_found(
    secondary_storage, accounts_storage, session_storage, rule
):
    auth = _auth(secondary_storage, accounts_storage, session_storage, rule)

    with pytest.raises(CrossAuthException) as exc:
        auth.issue_session_token("nobody")

    assert _error(exc.value) == REFUSED
    assert session_storage.records == {}


def test_without_a_rule_logins_do_not_load_the_user(
    secondary_storage, accounts_storage, session_storage
):
    auth = _auth(secondary_storage, accounts_storage, session_storage, None)

    with mock.patch.object(accounts_storage, "find_user_by_id") as find_user:
        auth.login("nobody", response=Response())
        auth.issue_session_token("nobody")

    find_user.assert_not_called()
    assert len(session_storage.records) == 2


def test_authenticate_checks_the_rule_only_after_the_password_matches(
    secondary_storage, accounts_storage, session_storage, rule
):
    auth = _auth(secondary_storage, accounts_storage, session_storage, rule)
    after: list[AfterAuthenticateEvent] = []
    auth.after("authenticate")(after.append)
    rule.refused.add("test")

    assert auth.authenticate("test@example.com", "wrong password") is None
    assert rule.checked == []

    with pytest.raises(CrossAuthException) as exc:
        auth.authenticate("test@example.com", TEST_PASSWORD)

    assert _error(exc.value) == REFUSED
    assert rule.checked == ["test"]
    # Only the failed attempt reached the after hook.
    assert [event.user for event in after] == [None]


def test_token_code_grant_refuses_a_user_the_rule_refuses(
    secondary_storage, accounts_storage, session_storage, rule, valid_code
):
    auth = _auth(
        secondary_storage,
        accounts_storage,
        session_storage,
        rule,
        oauth_server=OAuthServer(get_client=TEST_CLIENTS.get),
    )
    rule.refused.add("test")

    response = TestClient(_app(auth)).post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "client_id": "test",
            "code": valid_code,
            "redirect_uri": "http://valid-frontend.com/callback",
            "code_verifier": "test",
        },
    )

    # /token renders every CrossAuthException as a 400 OAuth error.
    assert response.status_code == 400
    assert response.json() == {
        "error": "access_denied",
        "error_description": "Sign-in is not allowed",
    }
    assert session_storage.records == {}


def test_token_code_grant_checks_before_a_custom_token_issuer(
    secondary_storage, accounts_storage, session_storage, rule, valid_code
):
    issuer = mock.Mock(return_value=("app-token", 60))
    auth = _auth(
        secondary_storage,
        accounts_storage,
        session_storage,
        rule,
        oauth_server=OAuthServer(get_client=TEST_CLIENTS.get, token_issuer=issuer),
    )
    rule.refused.add("test")
    rule.error = SUSPENDED

    response = TestClient(_app(auth)).post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "client_id": "test",
            "code": valid_code,
            "redirect_uri": "http://valid-frontend.com/callback",
            "code_verifier": "test",
        },
    )

    assert response.json() == {
        "error": "account_suspended",
        "error_description": "Account suspended",
    }
    issuer.assert_not_called()


def test_context_issue_token_refuses_with_a_custom_token_issuer(
    secondary_storage, accounts_storage, session_storage, rule
):
    issuer = mock.Mock(return_value=("app-token", 60))
    auth = _auth(
        secondary_storage,
        accounts_storage,
        session_storage,
        rule,
        oauth_server=OAuthServer(get_client=TEST_CLIENTS.get, token_issuer=issuer),
    )
    rule.refused.add("test")

    with pytest.raises(CrossAuthException) as exc:
        auth.router.context.issue_token(
            TokenIssueRequest(
                user_id="test",
                client_id="test",
                grant_type="authorization_code",
                scope=None,
                http_request=HTTPRequest.from_form_data(data={}),
            )
        )

    assert _error(exc.value) == REFUSED
    issuer.assert_not_called()


def test_password_grant_checks_the_rule_only_after_the_password_matches(
    secondary_storage, accounts_storage, session_storage, rule
):
    auth = _auth(
        secondary_storage,
        accounts_storage,
        session_storage,
        rule,
        oauth_server=LEGACY_PASSWORD_SERVER,
    )
    rule.refused.add("test")
    client = TestClient(_app(auth))
    grant = {
        "grant_type": "password",
        "client_id": "test",
        "username": "test@example.com",
    }

    with legacy_password_grant():
        wrong = client.post("/token", data={**grant, "password": "wrong"})
    assert wrong.json()["error"] == "invalid_grant"
    assert rule.checked == []

    with legacy_password_grant():
        right = client.post("/token", data={**grant, "password": TEST_PASSWORD})
    assert right.status_code == 400
    assert right.json()["error"] == "access_denied"
    assert session_storage.records == {}


# Session use


@time_machine.travel(NOW, tick=False)
def test_a_refused_cookie_session_is_unknown_and_not_extended(
    secondary_storage, accounts_storage, session_storage, rule
):
    auth = _auth(
        secondary_storage,
        accounts_storage,
        session_storage,
        rule,
        config={"session": SLIDING},
    )
    token, record = create_session("test", session_storage, max_age=60)
    client = TestClient(_app(auth), cookies={"session_id": token})
    rule.refused.add("test")

    with time_machine.travel(NOW + timedelta(seconds=20), tick=False):
        refused = client.get("/me")

    assert refused.json() == {"user": None}
    assert "set-cookie" not in refused.headers
    assert record.expires_at == NOW + timedelta(seconds=60)
    assert record.last_active_at == NOW
    # Refusing is not revoking: once allowed again, the session works.
    assert record.revoked_at is None

    rule.refused.clear()
    with time_machine.travel(NOW + timedelta(seconds=20), tick=False):
        allowed = client.get("/me")

    assert allowed.json() == {"user": "test"}
    assert f"session_id={token}" in allowed.headers["set-cookie"]
    assert record.expires_at == NOW + timedelta(seconds=80)


@time_machine.travel(NOW, tick=False)
def test_a_refused_bearer_session_is_unknown_and_not_extended(
    secondary_storage, accounts_storage, session_storage, rule
):
    auth = _auth(
        secondary_storage,
        accounts_storage,
        session_storage,
        rule,
        config={"session": SLIDING},
    )
    token, record = create_session("test", session_storage, max_age=60)
    client = TestClient(_app(auth), headers={"Authorization": f"Bearer {token}"})
    rule.refused.add("test")

    with time_machine.travel(NOW + timedelta(seconds=20), tick=False):
        me = client.get("/me")
        protected = client.get("/protected")

    assert me.json() == {"user": None}
    assert protected.status_code == 401
    assert record.expires_at == NOW + timedelta(seconds=60)


def test_a_rule_raising_on_use_propagates_its_error(
    secondary_storage, accounts_storage, session_storage, rule
):
    auth = _auth(secondary_storage, accounts_storage, session_storage, rule)
    token, _ = create_session("test", session_storage)
    client = TestClient(_app(auth), headers={"Authorization": f"Bearer {token}"})
    rule.refused.add("test")
    rule.error = SUSPENDED

    response = client.get("/protected")

    assert response.status_code == 403
    assert response.json() == {
        "error": "account_suspended",
        "error_description": "Account suspended",
    }


def test_get_current_session_ignores_a_refused_users_session(
    secondary_storage, accounts_storage, session_storage, rule
):
    auth = _auth(secondary_storage, accounts_storage, session_storage, rule)
    token, record = create_session("test", session_storage)
    app = FastAPI()

    @app.get("/session")
    def session(request: Request):
        current = auth.get_current_session(request)
        return {"session": None if current is None else current.id}

    client = TestClient(app, headers={"Authorization": f"Bearer {token}"})

    assert client.get("/session").json() == {"session": record.id}
    rule.refused.add("test")
    assert client.get("/session").json() == {"session": None}


@time_machine.travel(NOW, tick=False)
def test_authenticate_session_token_refuses_without_extending_the_session(
    secondary_storage, accounts_storage, session_storage, rule
):
    auth = _auth(
        secondary_storage,
        accounts_storage,
        session_storage,
        rule,
        config={"session": SLIDING},
    )
    token, record = create_session("test", session_storage, max_age=60)
    rule.refused.add("test")

    with time_machine.travel(NOW + timedelta(seconds=20), tick=False):
        assert auth.authenticate_session_token(token) is None
    assert record.expires_at == NOW + timedelta(seconds=60)

    rule.error = SUSPENDED
    with pytest.raises(CrossAuthException) as exc:
        auth.authenticate_session_token(token)
    assert exc.value is SUSPENDED

    rule.refused.clear()
    with time_machine.travel(NOW + timedelta(seconds=20), tick=False):
        result = auth.authenticate_session_token(token)
    assert result is not None
    assert result.user.id == "test"
    assert record.expires_at == NOW + timedelta(seconds=80)


@time_machine.travel(NOW, tick=False)
def test_a_custom_resolver_does_not_extend_a_refused_users_session(
    secondary_storage, accounts_storage, session_storage, rule
):
    # The implicit sliding refresh before a custom resolver is a session use
    # too; what the resolver returns is the application's own decision.
    auth = _auth(
        secondary_storage,
        accounts_storage,
        session_storage,
        rule,
        config={"session": SLIDING},
        get_user_from_request=lambda request: None,
    )
    token, record = create_session("test", session_storage, max_age=60)
    client = TestClient(_app(auth), cookies={"session_id": token})
    rule.refused.add("test")

    with time_machine.travel(NOW + timedelta(seconds=20), tick=False):
        client.get("/me")

    assert record.expires_at == NOW + timedelta(seconds=60)


def test_session_routes_refuse_a_user_the_rule_refuses(
    secondary_storage, accounts_storage, session_storage, rule
):
    auth = _auth(secondary_storage, accounts_storage, session_storage, rule)
    token, current = create_session("test", session_storage)
    _, other = create_session("test", session_storage)
    client = TestClient(_app(auth), headers={"Authorization": f"Bearer {token}"})
    rule.refused.add("test")

    responses = [
        client.get("/sessions"),
        client.delete(f"/sessions/{other.id}"),
        client.post("/sessions/revoke-others"),
    ]

    assert [response.status_code for response in responses] == [401, 401, 401]
    assert {response.json()["error"] for response in responses} == {"unauthorized"}
    assert current.revoked_at is None
    assert other.revoked_at is None

    rule.error = SUSPENDED
    suspended = client.get("/sessions")
    assert suspended.status_code == 403
    assert suspended.json() == {
        "error": "account_suspended",
        "error_description": "Account suspended",
    }


def test_logout_still_ends_a_refused_users_session(
    secondary_storage, accounts_storage, session_storage, rule
):
    auth = _auth(secondary_storage, accounts_storage, session_storage, rule)
    token, record = create_session("test", session_storage)
    client = TestClient(_app(auth), cookies={"session_id": token})
    rule.refused.add("test")
    rule.error = SUSPENDED

    response = client.post("/logout")

    assert response.status_code == 204
    assert record.revoked_at is not None
    assert 'session_id=""' in response.headers["set-cookie"]
    assert rule.checked == []


def test_without_a_rule_session_routes_do_not_load_the_user(
    secondary_storage, accounts_storage, session_storage
):
    auth = _auth(secondary_storage, accounts_storage, session_storage, None)
    token, _ = create_session("test", session_storage)
    client = TestClient(_app(auth), headers={"Authorization": f"Bearer {token}"})

    with mock.patch.object(accounts_storage, "find_user_by_id") as find_user:
        assert client.get("/sessions").status_code == 200

    find_user.assert_not_called()


def test_login_hooks_see_only_users_the_rule_allows(
    secondary_storage, accounts_storage, session_storage, rule
):
    auth = _auth(secondary_storage, accounts_storage, session_storage, rule)
    seen: list[BeforeLoginEvent] = []
    auth.before("login")(seen.append)
    rule.refused.add("test")

    with pytest.raises(CrossAuthException):
        auth.issue_session_token("test")
    accounts_storage.data["other"] = MemoryUser(
        id="other",
        email="other@example.com",
        email_verified=True,
        hashed_password=None,
        social_accounts=[],
    )
    auth.issue_session_token("other")

    assert [event.user_id for event in seen] == ["other"]
