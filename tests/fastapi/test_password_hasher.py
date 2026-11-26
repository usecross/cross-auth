"""``CrossAuth(password_hasher=...)`` verifies and hashes every password.

``authenticate``, the password grant and ``change_password`` verify passwords
with it, and ``change_password`` hands it to the accounts storage to hash the
new password. A hash it cannot read does not match, and no route answers 500.
"""

from typing import Any

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher
from pwdlib.hashers.bcrypt import BcryptHasher
from pydantic import BaseModel

from cross_auth import OAuthServer, PasswordHasher, SecondaryStorage
from cross_auth._password import DEFAULT_PASSWORD_HASHER
from cross_auth._session import create_session
from cross_auth.exceptions import CrossAuthException
from cross_auth.fastapi import CrossAuth
from cross_auth.router import AuthRouter

from ..conftest import (
    TEST_CLIENTS,
    TEST_PASSWORD,
    MemoryAccountsStorage,
    MemorySessionStorage,
    legacy_password_grant,
)
from ..conftest import User as MemoryUser

NEW_PASSWORD = "a new password"
# Cheap parameters: the tests only need real argon2 hashes.
ARGON2 = PasswordHash((Argon2Hasher(time_cost=1, memory_cost=1024),))
# An application moving from bcrypt to argon2: new hashes are argon2, and the
# bcrypt hashes users already have keep verifying.
MIGRATING = PasswordHash(
    (Argon2Hasher(time_cost=1, memory_cost=1024), BcryptHasher(rounds=4))
)
PASSWORD_SERVER = OAuthServer(get_client=TEST_CLIENTS.get, password_grant=True)


class PasswordChange(BaseModel):
    current_password: str | None = TEST_PASSWORD
    new_password: str = NEW_PASSWORD


class PasswordAccountsStorage(MemoryAccountsStorage):
    """The memory accounts storage, recording the hasher it hashes with."""

    def __init__(self, test_password_hash: str) -> None:
        super().__init__(test_password_hash)
        self.hashers: list[PasswordHasher] = []

    def set_password(
        self, user_id: Any, password: str, *, password_hasher: PasswordHasher
    ) -> MemoryUser | None:
        self.hashers.append(password_hasher)
        user = self.find_user_by_id(user_id)
        if user is None:
            return None
        user.hashed_password = password_hasher.hash(password)
        return user


@pytest.fixture
def accounts_storage(test_password_hash: str) -> PasswordAccountsStorage:
    return PasswordAccountsStorage(test_password_hash)


@pytest.fixture
def test_user(accounts_storage: PasswordAccountsStorage) -> MemoryUser:
    """The test user, whose password is a bcrypt hash."""
    return accounts_storage.data["test"]


def _auth(
    secondary_storage: SecondaryStorage,
    accounts_storage: MemoryAccountsStorage,
    session_storage: MemorySessionStorage,
    password_hasher: PasswordHasher | None,
) -> CrossAuth:
    return CrossAuth(
        providers=[],
        storage=secondary_storage,
        accounts_storage=accounts_storage,
        session_storage=session_storage,
        config={"session": {"cookies": {"secure": False}}},
        oauth_server=PASSWORD_SERVER,
        password_hasher=password_hasher,
    )


def _client(auth: CrossAuth) -> TestClient:
    app = FastAPI()
    app.include_router(auth.router)

    @app.exception_handler(CrossAuthException)
    def cross_auth_error(request: Request, exc: CrossAuthException) -> JSONResponse:
        return JSONResponse({"error": exc.error}, status_code=exc.status_code)

    @app.post("/change-password")
    def change_password(request: Request, body: PasswordChange):
        user = auth.change_password(
            request,
            current_password=body.current_password,
            new_password=body.new_password,
        )
        return {"user": user.id}

    return TestClient(app)


@pytest.fixture
def build(secondary_storage, accounts_storage, session_storage):
    def make(password_hasher: PasswordHasher | None) -> CrossAuth:
        return _auth(
            secondary_storage, accounts_storage, session_storage, password_hasher
        )

    return make


def _password_grant(client: TestClient, password: str = TEST_PASSWORD):
    with legacy_password_grant():
        return client.post(
            "/token",
            data={
                "grant_type": "password",
                "client_id": "test",
                "username": "test@example.com",
                "password": password,
            },
        )


def test_bcrypt_is_the_default(build, test_user):
    auth = build(None)

    assert auth.password_hasher is DEFAULT_PASSWORD_HASHER
    assert auth.router.context.password_hasher is DEFAULT_PASSWORD_HASHER
    assert auth.authenticate("test@example.com", TEST_PASSWORD) is test_user


def test_auth_router_takes_the_hasher(
    secondary_storage, accounts_storage, session_storage
):
    router = AuthRouter(
        providers=[],
        secondary_storage=secondary_storage,
        accounts_storage=accounts_storage,
        get_user_from_request=lambda request: None,
        session_storage=session_storage,
        password_hasher=ARGON2,
    )

    assert router.context.password_hasher is ARGON2


def test_authenticate_verifies_with_the_hasher(build, test_user):
    auth = build(ARGON2)
    test_user.hashed_password = ARGON2.hash(TEST_PASSWORD)

    assert auth.authenticate("test@example.com", TEST_PASSWORD) is test_user
    assert auth.authenticate("test@example.com", "wrong password") is None
    assert auth.authenticate("unknown@example.com", TEST_PASSWORD) is None


def test_authenticate_does_not_match_a_hash_the_hasher_cannot_read(build, test_user):
    # pwdlib raises UnknownHashError for the bcrypt hash.
    auth = build(ARGON2)

    assert auth.authenticate("test@example.com", TEST_PASSWORD) is None


def test_a_hasher_with_bcrypt_reads_the_hashes_users_have(build, test_user):
    auth = build(MIGRATING)

    assert auth.authenticate("test@example.com", TEST_PASSWORD) is test_user


def test_the_password_grant_verifies_with_the_hasher(build, test_user):
    client = _client(build(ARGON2))
    test_user.hashed_password = ARGON2.hash(TEST_PASSWORD)

    signed_in = _password_grant(client)
    refused = _password_grant(client, "wrong password")

    assert signed_in.status_code == 200
    assert signed_in.json()["access_token"]
    assert (refused.status_code, refused.json()["error"]) == (400, "invalid_grant")


def test_the_password_grant_refuses_a_hash_the_hasher_cannot_read(build, test_user):
    client = _client(build(ARGON2))

    response = _password_grant(client)

    assert (response.status_code, response.json()["error"]) == (400, "invalid_grant")


def test_change_password_verifies_and_hashes_with_the_hasher(
    build, accounts_storage, session_storage, test_user
):
    auth = build(MIGRATING)
    client = _client(auth)
    token, _ = create_session("test", session_storage)

    response = client.post(
        "/change-password",
        headers={"Authorization": f"Bearer {token}"},
        json={},
    )

    assert response.json() == {"user": "test"}
    assert accounts_storage.hashers == [MIGRATING]
    assert test_user.hashed_password is not None
    assert test_user.hashed_password.startswith("$argon2id$")
    assert auth.authenticate("test@example.com", NEW_PASSWORD) is test_user


def test_change_password_refuses_a_hash_the_hasher_cannot_read(
    build, accounts_storage, session_storage, test_user
):
    hashed_password = test_user.hashed_password
    client = _client(build(ARGON2))
    token, _ = create_session("test", session_storage)

    response = client.post(
        "/change-password",
        headers={"Authorization": f"Bearer {token}"},
        json={},
    )

    assert (response.status_code, response.json()) == (
        400,
        {"error": "invalid_password"},
    )
    assert accounts_storage.hashers == []
    assert test_user.hashed_password == hashed_password
