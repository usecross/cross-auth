"""Soft-deleted users stay visible to the storage, and the rule refuses them.

``filter_user_query`` could hide them, but sign-in then breaks: their
provider identity points at a user that is not found, and their email looks
free for a second sign-up. Here the SQLModel storage returns them, and
``user_can_authenticate`` returns its own error for them. Every path that
finds such a user, by provider identity, by email or by ID, answers with that
error, creates no second user and never answers ``server_error``.
"""

from collections.abc import Iterator
from typing import Annotated, Any
from urllib.parse import parse_qs, urlparse

import pytest
import respx
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlmodel import Session, col, func, select

from cross_auth import SecondaryStorage
from cross_auth import User as UserProtocol
from cross_auth._password import hash_password
from cross_auth._session import create_session
from cross_auth.exceptions import CrossAuthException
from cross_auth.fastapi import CrossAuth
from cross_auth.utils._pkce import calculate_s256_challenge

from ..conftest import legacy_password_grant
from ..fastapi.test_id_token_sign_in import VALID_TOKEN, StubOIDCProvider
from ..storage.conftest import make_sqlite_engine
from ..storage.models import AccountsStore, SessionStore, SocialAccount, User
from .conftest import (
    LEGACY_APP_OAUTH_SERVER,
    FakeProvider,
    mock_token_and_userinfo,
    start_provider_auth,
)
from .test_token_flow import _AUTHZ_PARAMS

EMAIL = "gone@example.com"
PASSWORD = "correct horse"  # noqa: S105
DELETED = {
    "error": "account_deleted",
    "error_description": "This account was deleted. Contact support to restore it.",
}


def user_can_authenticate(user: UserProtocol) -> bool | CrossAuthException:
    if isinstance(user, User) and user.deleted:
        return CrossAuthException(
            DELETED["error"], DELETED["error_description"], status_code=403
        )
    return True


@pytest.fixture
def engine() -> Iterator[Engine]:
    engine = make_sqlite_engine()
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.fixture
def accounts(engine: Engine) -> AccountsStore:
    return AccountsStore(session_factory=lambda: Session(engine))


@pytest.fixture
def sessions(engine: Engine) -> SessionStore:
    return SessionStore(session_factory=lambda: Session(engine))


@pytest.fixture
def user(engine: Engine, accounts: AccountsStore) -> User:
    """A user with a password and a provider identity for each provider."""
    user = accounts.create_user(user_info={}, email=EMAIL, email_verified=True)
    with Session(engine) as db:
        row = db.get_one(User, user.id)
        assert row.id is not None
        row.hashed_password = hash_password(PASSWORD)
        db.add(row)
        for provider in ("fake", "stub"):
            db.add(
                SocialAccount(
                    user_id=row.id,
                    provider=provider,
                    provider_user_id=f"{provider}-user-1",
                    provider_email=EMAIL,
                    provider_email_verified=True,
                    is_login_method=True,
                    access_token="stored-access",
                )
            )
        db.commit()
    return user


def _delete(engine: Engine, user: User) -> None:
    with Session(engine) as db:
        row = db.get_one(User, user.id)
        row.deleted = True
        db.add(row)
        db.commit()


@pytest.fixture
def deleted(engine: Engine, user: User) -> User:
    _delete(engine, user)
    return user


def _make_auth(
    secondary_storage: SecondaryStorage,
    accounts: AccountsStore,
    sessions: SessionStore,
    *,
    auto_link: bool = True,
) -> CrossAuth:
    return CrossAuth(
        providers=[
            FakeProvider(client_id="fake-client-id", client_secret="fake-secret"),
            StubOIDCProvider(
                {"sub": "stub-user-1", "email": EMAIL, "email_verified": True}
            ),
        ],
        storage=secondary_storage,
        accounts_storage=accounts,
        session_storage=sessions,
        config={
            "session": {"cookies": {"auth": True, "secure": False}},
            "account_linking": {"enabled": auto_link},
        },
        oauth_server=LEGACY_APP_OAUTH_SERVER,
        user_can_authenticate=user_can_authenticate,
    )


@pytest.fixture
def auth(
    secondary_storage: SecondaryStorage,
    accounts: AccountsStore,
    sessions: SessionStore,
) -> CrossAuth:
    return _make_auth(secondary_storage, accounts, sessions)


def _client(auth: CrossAuth) -> TestClient:
    app = FastAPI()
    app.include_router(auth.router)

    @app.get("/me")
    def me(user: Annotated[Any, Depends(auth.get_current_user)]):
        return {"user": None if user is None else user.id}

    return TestClient(app, follow_redirects=False)


def _counts(engine: Engine) -> tuple[int, int, int]:
    """How many users, identities and sessions are stored."""
    with Session(engine) as db:
        return (
            db.exec(select(func.count()).select_from(User)).one(),
            db.exec(select(func.count()).select_from(SocialAccount)).one(),
            db.exec(select(func.count(col(SessionStore.SessionModel.id)))).one(),
        )


def _browser_sign_in(
    auth: CrossAuth, *, provider_user_id: str, path: str = "/fake/login", **kwargs
):
    mock_token_and_userinfo(email=EMAIL, provider_user_id=provider_user_id)
    with _client(auth) as client:
        _, state = start_provider_auth(client, path, **kwargs)
        return client.get(
            "/fake/callback", params={"code": "provider-code", "state": state}
        )


@respx.mock
def test_provider_sign_in_by_identity_answers_the_rules_error(auth, engine, deleted):
    before = _counts(engine)

    response = _browser_sign_in(auth, provider_user_id="fake-user-1")

    assert response.status_code == 403
    assert response.json() == DELETED
    assert "session_id" not in response.cookies
    assert _counts(engine) == before


@respx.mock
def test_provider_sign_in_by_email_neither_signs_up_nor_links(auth, engine, deleted):
    # A new identity with the deleted user's email is auto-linked to them, so
    # it is refused, and gets no identity of its own.
    before = _counts(engine)

    response = _browser_sign_in(auth, provider_user_id="new-identity")

    assert response.status_code == 403
    assert response.json() == DELETED
    assert _counts(engine) == before


@respx.mock
def test_an_email_that_is_not_linked_automatically_is_not_asked_about(
    secondary_storage, accounts, sessions, engine, deleted
):
    # Without auto-linking the identity has not shown it owns the account, so
    # it learns only that the email is taken, as for an active user.
    auth = _make_auth(secondary_storage, accounts, sessions, auto_link=False)
    before = _counts(engine)

    response = _browser_sign_in(auth, provider_user_id="new-identity")

    assert response.status_code == 400
    assert response.json()["error"] == "account_not_linked"
    assert _counts(engine) == before


@respx.mock
def test_an_oauth_client_gets_the_rules_error_at_its_redirect_uri(
    auth, engine, deleted
):
    before = _counts(engine)

    response = _browser_sign_in(
        auth,
        provider_user_id="fake-user-1",
        path="/fake/authorize",
        params=_AUTHZ_PARAMS,
    )

    assert response.status_code == 302
    assert parse_qs(urlparse(response.headers["location"]).query) == {
        "error": [DELETED["error"]],
        "error_description": [DELETED["error_description"]],
        "state": ["client-csrf-state"],
    }
    assert _counts(engine) == before


@pytest.mark.parametrize("sub", ["stub-user-1", "new-identity"])
def test_id_token_sign_in_answers_the_rules_error(
    secondary_storage, accounts, sessions, engine, deleted, sub
):
    auth = _make_auth(secondary_storage, accounts, sessions)
    stub = auth._setup.providers_by_id["stub"]
    assert isinstance(stub, StubOIDCProvider)
    stub.claims["sub"] = sub
    before = _counts(engine)

    with pytest.raises(CrossAuthException) as exc:
        auth.sign_in_with_id_token("stub", VALID_TOKEN)

    assert (exc.value.error, exc.value.error_description) == tuple(DELETED.values())
    assert _counts(engine) == before


def test_password_sign_in_answers_the_rules_error(auth, engine, deleted):
    assert auth.authenticate(EMAIL, "wrong password") is None
    with pytest.raises(CrossAuthException) as exc:
        auth.authenticate(EMAIL, PASSWORD)
    assert exc.value.error == DELETED["error"]

    with legacy_password_grant(), _client(auth) as client:
        response = client.post(
            "/token",
            data={
                "grant_type": "password",
                "client_id": "app-client",
                "username": EMAIL,
                "password": PASSWORD,
            },
        )
    assert response.status_code == 400
    assert response.json() == DELETED
    assert _counts(engine)[2] == 0


def test_logins_by_user_id_answer_the_rules_error(auth, engine, deleted):
    with pytest.raises(CrossAuthException) as token:
        auth.issue_session_token(str(deleted.id))

    assert token.value.error == DELETED["error"]
    assert _counts(engine)[2] == 0


def test_a_deleted_users_sessions_count_as_none(auth, engine, sessions, user):
    token, record = create_session(str(user.id), sessions)
    with _client(auth) as client:
        client.cookies.set("session_id", token)
        assert client.get("/me").json() == {"user": user.id}

        _delete(engine, user)

        assert client.get("/me").json() == {"user": None}
        listed = client.get("/sessions")
    assert listed.status_code == 401
    assert listed.json()["error"] == "unauthorized"
    assert auth.authenticate_session_token(token) is None
    with Session(engine) as db:
        assert auth.authenticate_session_token(token, db_session=db) is None
    # Refused, not revoked: restoring the user restores their sessions.
    stored = sessions.get_any(record.id)
    assert stored is not None
    assert stored.revoked_at is None


@respx.mock
def test_a_code_redeemed_after_the_deletion_gets_no_token(auth, engine, user):
    verifier = "v" * 64
    params = {**_AUTHZ_PARAMS, "code_challenge": calculate_s256_challenge(verifier)}
    signed_in = _browser_sign_in(
        auth, provider_user_id="fake-user-1", path="/fake/authorize", params=params
    )
    [code] = parse_qs(urlparse(signed_in.headers["location"]).query)["code"]

    _delete(engine, user)
    with _client(auth) as client:
        response = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": "app-client",
                "code": code,
                "redirect_uri": params["redirect_uri"],
                "code_verifier": verifier,
            },
        )

    assert response.status_code == 400
    assert response.json() == DELETED
    assert _counts(engine)[2] == 0
