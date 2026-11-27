"""Password sign-ins check the password again once their session is stored.

A password change stores the new hash, then revokes the user's sessions. A
sign-in that checked the old password just before the change, and stored its
session just after the revocation, would keep a session the change meant to
end. ``CrossAuth.sign_in_with_password``, ``CrossAuth.login_with_password`` and
the deprecated ``/token`` password grant check the stored hash again once their
credential is stored: the change either revokes that session or is found by the
check.

The tests change the password from a ``login`` before hook, which runs after
the password is checked and before the session is stored.
"""

from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi import FastAPI, Response
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from cross_auth import OAuthServer, SecondaryStorage, TokenIssueRequest
from cross_auth._session import get_session
from cross_auth.exceptions import CrossAuthException
from cross_auth.fastapi import CrossAuth, PasswordSignIn
from cross_auth.hooks import AfterLoginEvent, BeforeLoginEvent

from ..conftest import (
    TEST_CLIENTS,
    TEST_PASSWORD,
    DeferredSessionStorage,
    MemoryAccountsStorage,
    MemorySessionStorage,
)
from ..router.test_commit_callbacks import TransactionalAccountsStorage
from ..storage.conftest import make_sqlite_engine
from ..storage.models import AccountsStore, SessionStore, User, UserSession

EMAIL = "test@example.com"
NEW_PASSWORD = "a new password"
PASSWORD_GRANT = {
    "grant_type": "password",
    "client_id": "test",
    "username": EMAIL,
    "password": TEST_PASSWORD,
}
INVALID_GRANT = {
    "error": "invalid_grant",
    "error_description": "Invalid username or password",
}

grant_warning = pytest.mark.filterwarnings(
    "ignore:The OAuth password grant is deprecated:DeprecationWarning"
)


def _auth(
    secondary_storage: SecondaryStorage,
    accounts_storage: MemoryAccountsStorage,
    session_storage: MemorySessionStorage,
    **kwargs: Any,
) -> CrossAuth:
    return CrossAuth(
        providers=[],
        storage=secondary_storage,
        accounts_storage=accounts_storage,
        session_storage=session_storage,
        oauth_server=OAuthServer(get_client=TEST_CLIENTS.get, password_grant=True),
        **kwargs,
    )


def _grant(auth: CrossAuth) -> dict[str, Any]:
    app = FastAPI()
    app.include_router(auth.router)
    response = TestClient(app).post("/token", data=PASSWORD_GRANT)
    return {"status": response.status_code, **response.json()}


def _change_password(
    auth: CrossAuth,
    accounts_storage: MemoryAccountsStorage,
    session_storage: MemorySessionStorage,
) -> Callable[[BeforeLoginEvent], None]:
    """A password change as change_password makes it: new hash, then revoke."""

    def change(_event: BeforeLoginEvent) -> None:
        user = accounts_storage.data["test"]
        user.hashed_password = auth.password_hasher.hash(NEW_PASSWORD)
        session_storage.revoke_all_for_user("test", revoked_at=datetime.now(UTC))

    return change


def _rehash_password(
    auth: CrossAuth, accounts_storage: MemoryAccountsStorage
) -> Callable[[BeforeLoginEvent], None]:
    """The same password stored again, with a new salt."""

    def rehash(_event: BeforeLoginEvent) -> None:
        user = accounts_storage.data["test"]
        user.hashed_password = auth.password_hasher.hash(TEST_PASSWORD)

    return rehash


def _remove_user(
    accounts_storage: MemoryAccountsStorage,
) -> Callable[[BeforeLoginEvent], None]:
    def remove(_event: BeforeLoginEvent) -> None:
        del accounts_storage.data["test"]

    return remove


def _only_session(session_storage: MemorySessionStorage) -> Any:
    [record] = session_storage.records.values()
    return record


def _cookie_sign_in(auth: CrossAuth, password: str = TEST_PASSWORD) -> Any:
    """Post to an endpoint that signs in with login_with_password."""
    app = FastAPI()

    @app.post("/sign-in")
    def sign_in(response: Response) -> dict[str, str | None]:
        user = auth.login_with_password(
            EMAIL, password, response=response, metadata={"client_name": "Web"}
        )
        return {"user": None if user is None else user.id}

    return TestClient(app).post("/sign-in")


def test_sign_in_with_password_issues_a_bearer_session(
    secondary_storage, accounts_storage, session_storage
):
    auth = _auth(secondary_storage, accounts_storage, session_storage)
    logins: list[AfterLoginEvent] = []
    auth.after("login")(logins.append)

    signed_in = auth.sign_in_with_password(
        EMAIL, TEST_PASSWORD, metadata={"client_name": "CLI"}
    )

    assert isinstance(signed_in, PasswordSignIn)
    assert signed_in.user.id == "test"
    session = get_session(signed_in.token, session_storage)
    assert session is not None
    assert session.id == signed_in.session_record.id
    assert session.login_method == "password"
    assert session.client_name == "CLI"
    assert [(event.credential, event.login_method) for event in logins] == [
        ("bearer", "password")
    ]


def test_sign_in_with_password_runs_the_authenticate_hooks(
    secondary_storage, accounts_storage, session_storage
):
    auth = _auth(secondary_storage, accounts_storage, session_storage)
    auth.before("authenticate")(lambda event: replace(event, email=event.email.strip()))

    assert auth.sign_in_with_password(f"  {EMAIL} ", TEST_PASSWORD) is not None


@pytest.mark.parametrize(
    ("email", "password"),
    [(EMAIL, "wrong-password"), ("nobody@example.com", TEST_PASSWORD)],
)
def test_sign_in_with_password_returns_none_for_wrong_credentials(
    secondary_storage, accounts_storage, session_storage, email: str, password: str
):
    auth = _auth(secondary_storage, accounts_storage, session_storage)

    assert auth.sign_in_with_password(email, password) is None
    assert not session_storage.records


def test_sign_in_with_password_raises_what_user_can_authenticate_refuses(
    secondary_storage, accounts_storage, session_storage
):
    refusal = CrossAuthException("account_locked", "Locked", status_code=403)
    auth = _auth(
        secondary_storage,
        accounts_storage,
        session_storage,
        user_can_authenticate=lambda _user: refusal,
    )

    with pytest.raises(CrossAuthException) as raised:
        auth.sign_in_with_password(EMAIL, TEST_PASSWORD)

    assert raised.value.error == "account_locked"
    assert not session_storage.records


def test_password_changed_during_sign_in_is_refused(
    secondary_storage, accounts_storage, session_storage
):
    auth = _auth(secondary_storage, accounts_storage, session_storage)
    auth.before("login")(_change_password(auth, accounts_storage, session_storage))
    logins: list[AfterLoginEvent] = []
    auth.after("login")(logins.append)

    assert auth.sign_in_with_password(EMAIL, TEST_PASSWORD) is None

    # Stored after the change revoked the user's sessions, then revoked here.
    assert _only_session(session_storage).revoked_at is not None
    assert logins == []


def test_password_rehashed_during_sign_in_still_signs_in(
    secondary_storage, accounts_storage, session_storage
):
    auth = _auth(secondary_storage, accounts_storage, session_storage)
    auth.before("login")(_rehash_password(auth, accounts_storage))

    signed_in = auth.sign_in_with_password(EMAIL, TEST_PASSWORD)

    assert signed_in is not None
    assert get_session(signed_in.token, session_storage) is not None


def test_user_removed_during_sign_in_is_refused(
    secondary_storage, accounts_storage, session_storage
):
    auth = _auth(secondary_storage, accounts_storage, session_storage)
    auth.before("login")(_remove_user(accounts_storage))

    assert auth.sign_in_with_password(EMAIL, TEST_PASSWORD) is None
    assert _only_session(session_storage).revoked_at is not None


def test_sign_in_with_password_refuses_a_session_storage_that_defers_commits(
    secondary_storage, accounts_storage
):
    session_storage = DeferredSessionStorage()
    auth = _auth(secondary_storage, accounts_storage, session_storage)

    with pytest.raises(RuntimeError):
        auth.sign_in_with_password(EMAIL, TEST_PASSWORD)

    assert not session_storage.records


def test_sign_in_with_password_refuses_an_accounts_storage_that_defers_commits(
    secondary_storage, session_storage, test_password_hash: str
):
    accounts_storage = TransactionalAccountsStorage(test_password_hash)
    auth = _auth(secondary_storage, accounts_storage, session_storage)

    with pytest.raises(RuntimeError), accounts_storage.atomic():
        auth.sign_in_with_password(EMAIL, TEST_PASSWORD)

    assert not session_storage.records


@pytest.mark.parametrize(
    ("new_password", "signed_in"), [(NEW_PASSWORD, False), (TEST_PASSWORD, True)]
)
def test_sign_in_with_password_reads_the_stored_hash_again(
    secondary_storage: SecondaryStorage,
    request: pytest.FixtureRequest,
    new_password: str,
    signed_in: bool,
):
    # The storages read in their own database sessions: the second check must
    # see what another transaction committed, not the user the first check read.
    engine = make_sqlite_engine()
    request.addfinalizer(engine.dispose)
    accounts_storage = AccountsStore(session_factory=lambda: Session(engine))
    session_storage = SessionStore(session_factory=lambda: Session(engine))
    auth = CrossAuth(
        providers=[],
        storage=secondary_storage,
        accounts_storage=accounts_storage,
        session_storage=session_storage,
    )
    with Session(engine) as db:
        user = User(
            email=EMAIL,
            email_verified=True,
            hashed_password=auth.password_hasher.hash(TEST_PASSWORD),
        )
        db.add(user)
        db.commit()
        user_id = user.id

    @auth.before("login")
    def change(_event: BeforeLoginEvent) -> None:
        with Session(engine) as db:
            stored = db.get_one(User, user_id)
            stored.hashed_password = auth.password_hasher.hash(new_password)
            db.add(stored)
            db.commit()
        session_storage.revoke_all_for_user(str(user_id), revoked_at=datetime.now(UTC))

    result = auth.sign_in_with_password(EMAIL, TEST_PASSWORD)

    assert (result is not None) is signed_in
    with Session(engine) as db:
        [stored_session] = db.exec(select(UserSession)).all()
    assert (stored_session.revoked_at is None) is signed_in


def test_login_with_password_sets_the_session_cookie(
    secondary_storage, accounts_storage, session_storage
):
    auth = _auth(secondary_storage, accounts_storage, session_storage)
    logins: list[AfterLoginEvent] = []
    auth.after("login")(logins.append)

    response = _cookie_sign_in(auth)

    assert response.json() == {"user": "test"}
    session = get_session(response.cookies["session_id"], session_storage)
    assert session is not None
    assert session.login_method == "password"
    assert session.client_name == "Web"
    assert [(event.credential, event.login_method) for event in logins] == [
        ("cookie", "password")
    ]


def test_login_with_password_leaves_the_response_for_wrong_credentials(
    secondary_storage, accounts_storage, session_storage
):
    auth = _auth(secondary_storage, accounts_storage, session_storage)

    response = _cookie_sign_in(auth, password="wrong-password")

    assert response.json() == {"user": None}
    assert "set-cookie" not in response.headers
    assert not session_storage.records


def test_login_with_password_refuses_a_password_changed_during_sign_in(
    secondary_storage, accounts_storage, session_storage
):
    auth = _auth(secondary_storage, accounts_storage, session_storage)
    auth.before("login")(_change_password(auth, accounts_storage, session_storage))
    logins: list[AfterLoginEvent] = []
    auth.after("login")(logins.append)

    response = _cookie_sign_in(auth)

    assert response.json() == {"user": None}
    assert "set-cookie" not in response.headers
    assert _only_session(session_storage).revoked_at is not None
    assert logins == []


def test_login_with_password_survives_a_rehash_during_sign_in(
    secondary_storage, accounts_storage, session_storage
):
    auth = _auth(secondary_storage, accounts_storage, session_storage)
    auth.before("login")(_rehash_password(auth, accounts_storage))

    response = _cookie_sign_in(auth)

    assert response.json() == {"user": "test"}
    assert "session_id" in response.cookies


def test_login_with_password_refuses_a_session_storage_that_defers_commits(
    secondary_storage, accounts_storage
):
    session_storage = DeferredSessionStorage()
    auth = _auth(secondary_storage, accounts_storage, session_storage)

    with pytest.raises(RuntimeError):
        auth.login_with_password(EMAIL, TEST_PASSWORD, response=Response())

    assert not session_storage.records


@grant_warning
def test_password_grant_refuses_a_password_changed_during_sign_in(
    secondary_storage, accounts_storage, session_storage
):
    auth = _auth(secondary_storage, accounts_storage, session_storage)
    auth.before("login")(_change_password(auth, accounts_storage, session_storage))
    logins: list[AfterLoginEvent] = []
    auth.after("login")(logins.append)

    assert _grant(auth) == {"status": 400, **INVALID_GRANT}
    assert _only_session(session_storage).revoked_at is not None
    assert logins == []


@grant_warning
def test_password_grant_survives_a_rehash_during_sign_in(
    secondary_storage, accounts_storage, session_storage
):
    auth = _auth(secondary_storage, accounts_storage, session_storage)
    auth.before("login")(_rehash_password(auth, accounts_storage))

    assert _grant(auth)["status"] == 200
    assert _only_session(session_storage).revoked_at is None


@grant_warning
def test_password_grant_refuses_a_user_removed_during_sign_in(
    secondary_storage, accounts_storage, session_storage
):
    auth = _auth(secondary_storage, accounts_storage, session_storage)
    auth.before("login")(_remove_user(accounts_storage))

    assert _grant(auth) == {"status": 400, **INVALID_GRANT}
    assert _only_session(session_storage).revoked_at is not None


@grant_warning
def test_password_grant_withholds_a_token_issuer_credential_after_a_change(
    secondary_storage, accounts_storage, session_storage
):
    issued: list[TokenIssueRequest] = []

    def token_issuer(request: TokenIssueRequest) -> tuple[str, int]:
        issued.append(request)
        return "issuer-token", 3600

    auth = CrossAuth(
        providers=[],
        storage=secondary_storage,
        accounts_storage=accounts_storage,
        session_storage=session_storage,
        oauth_server=OAuthServer(
            get_client=TEST_CLIENTS.get,
            password_grant=True,
            token_issuer=token_issuer,
        ),
    )
    auth.before("login")(_change_password(auth, accounts_storage, session_storage))

    result = _grant(auth)

    # Core cannot revoke what the issuer minted: it is never handed out.
    assert result == {"status": 400, **INVALID_GRANT}
    assert len(issued) == 1
