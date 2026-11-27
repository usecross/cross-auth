"""Password checks store the upgraded hash of a password whose hash is outdated.

With a ``RehashingPasswordHasher`` (pwdlib's ``PasswordHash`` here) and an
accounts storage that can replace a hash, a matching password whose hash the
hasher calls outdated is stored with its new hash. The storage replaces it only
if it still stores the hash that was checked, so a password changed in between
keeps its own. Nothing about an upgrade can refuse a matching password.
"""

from datetime import datetime, timedelta
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher
from pwdlib.hashers.bcrypt import BcryptHasher
from sqlmodel import Session

from cross_auth import (
    OAuthServer,
    PasswordHasher,
    PasswordHashStorage,
    RehashingPasswordHasher,
    SecondaryStorage,
)
from cross_auth.fastapi import CrossAuth

from ..conftest import TEST_CLIENTS, TEST_PASSWORD, MemoryAccountsStorage
from ..storage.conftest import make_sqlite_engine
from ..storage.models import AccountsStore, SessionStore, User

EMAIL = "test@example.com"
NEW_PASSWORD = "a new password"

# Argon2 is current; the bcrypt hashes the fixtures store are outdated.
UPGRADING_HASHER = PasswordHash((Argon2Hasher(), BcryptHasher()))


class UpgradableAccountsStorage(MemoryAccountsStorage):
    """The memory accounts storage, able to replace a hash it still stores."""

    def __init__(self, test_password_hash: str) -> None:
        super().__init__(test_password_hash)
        self.replacements: list[tuple[str, str]] = []

    def replace_password_hash(
        self, user_id: Any, *, old_hash: str, new_hash: str
    ) -> bool:
        self.replacements.append((old_hash, new_hash))
        user = self.find_user_by_id(user_id)
        if user is None or user.hashed_password != old_hash:
            return False
        user.hashed_password = new_hash
        return True


class FailingAccountsStorage(UpgradableAccountsStorage):
    def replace_password_hash(
        self, user_id: Any, *, old_hash: str, new_hash: str
    ) -> bool:
        # As a database error does, quote the statement's parameters.
        raise RuntimeError(f"UPDATE failed with {old_hash!r} and {new_hash!r}")


class HasherThatFailsToUpgrade:
    """Verifies like pwdlib, but making the new hash fails after a match."""

    def hash(self, password: str, /) -> str:
        return UPGRADING_HASHER.hash(password)

    def verify(self, password: str, hash: str, /) -> bool:
        return UPGRADING_HASHER.verify(password, hash)

    def verify_and_update(self, password: str, hash: str, /) -> tuple[bool, str | None]:
        raise RuntimeError("Could not make the new hash")


def _auth(
    secondary_storage: SecondaryStorage,
    accounts_storage: Any,
    session_storage: Any,
    password_hasher: PasswordHasher = UPGRADING_HASHER,
) -> CrossAuth:
    return CrossAuth(
        providers=[],
        storage=secondary_storage,
        accounts_storage=accounts_storage,
        session_storage=session_storage,
        oauth_server=OAuthServer(get_client=TEST_CLIENTS.get, password_grant=True),
        password_hasher=password_hasher,
    )


def _stored_hash(accounts_storage: MemoryAccountsStorage) -> str | None:
    return accounts_storage.data["test"].hashed_password


def test_pwdlib_and_the_upgrading_storage_have_the_capabilities(
    test_password_hash: str,
):
    assert isinstance(UPGRADING_HASHER, RehashingPasswordHasher)
    assert isinstance(
        UpgradableAccountsStorage(test_password_hash), PasswordHashStorage
    )
    assert not isinstance(
        MemoryAccountsStorage(test_password_hash), PasswordHashStorage
    )


def _authenticate(auth: CrossAuth) -> bool:
    return auth.authenticate(EMAIL, TEST_PASSWORD) is not None


def _password_grant(auth: CrossAuth) -> bool:
    app = FastAPI()
    app.include_router(auth.router)
    response = TestClient(app).post(
        "/token",
        data={
            "grant_type": "password",
            "client_id": "test",
            "username": EMAIL,
            "password": TEST_PASSWORD,
        },
    )
    return response.status_code == 200


@pytest.mark.filterwarnings(
    "ignore:The OAuth password grant is deprecated:DeprecationWarning"
)
@pytest.mark.parametrize("sign_in", [_authenticate, _password_grant])
def test_sign_in_upgrades_an_outdated_hash(
    secondary_storage, session_storage, test_password_hash: str, sign_in
):
    accounts_storage = UpgradableAccountsStorage(test_password_hash)
    auth = _auth(secondary_storage, accounts_storage, session_storage)

    assert sign_in(auth)

    stored = _stored_hash(accounts_storage)
    assert stored is not None
    assert stored.startswith("$argon2")
    assert UPGRADING_HASHER.verify(TEST_PASSWORD, stored)


def test_current_hash_is_left_alone(secondary_storage, session_storage):
    accounts_storage = UpgradableAccountsStorage(UPGRADING_HASHER.hash(TEST_PASSWORD))
    current = _stored_hash(accounts_storage)
    auth = _auth(secondary_storage, accounts_storage, session_storage)

    assert auth.authenticate(EMAIL, TEST_PASSWORD) is not None

    assert _stored_hash(accounts_storage) == current
    assert accounts_storage.replacements == []


def test_wrong_password_writes_nothing(
    secondary_storage, session_storage, test_password_hash: str
):
    accounts_storage = UpgradableAccountsStorage(test_password_hash)
    auth = _auth(secondary_storage, accounts_storage, session_storage)

    assert auth.authenticate(EMAIL, "wrong-password") is None

    assert _stored_hash(accounts_storage) == test_password_hash
    assert accounts_storage.replacements == []


def test_unreadable_hash_is_no_match_and_writes_nothing(
    secondary_storage, session_storage
):
    accounts_storage = UpgradableAccountsStorage("not-a-hash")
    auth = _auth(secondary_storage, accounts_storage, session_storage)

    assert auth.authenticate(EMAIL, TEST_PASSWORD) is None

    assert accounts_storage.replacements == []


def test_storage_that_cannot_replace_hashes_keeps_the_old_one(
    secondary_storage, accounts_storage, session_storage, test_password_hash: str
):
    auth = _auth(secondary_storage, accounts_storage, session_storage)

    assert auth.authenticate(EMAIL, TEST_PASSWORD) is not None

    assert _stored_hash(accounts_storage) == test_password_hash


def test_hasher_that_cannot_upgrade_keeps_the_old_hash(
    secondary_storage, session_storage, test_password_hash: str
):
    accounts_storage = UpgradableAccountsStorage(test_password_hash)
    # The default bcrypt hasher has no verify_and_update.
    auth = CrossAuth(
        providers=[],
        storage=secondary_storage,
        accounts_storage=accounts_storage,
        session_storage=session_storage,
    )

    assert auth.authenticate(EMAIL, TEST_PASSWORD) is not None

    assert accounts_storage.replacements == []


def test_failed_replacement_still_signs_in_and_logs_no_hash(
    secondary_storage,
    session_storage,
    test_password_hash: str,
    caplog: pytest.LogCaptureFixture,
):
    accounts_storage = FailingAccountsStorage(test_password_hash)
    auth = _auth(secondary_storage, accounts_storage, session_storage)

    with caplog.at_level("WARNING", logger="cross_auth._password"):
        assert auth.authenticate(EMAIL, TEST_PASSWORD) is not None

    assert _stored_hash(accounts_storage) == test_password_hash
    assert "RuntimeError" in caplog.text
    assert test_password_hash not in caplog.text
    assert "$argon2" not in caplog.text


def test_failed_upgrade_still_signs_in(
    secondary_storage, session_storage, test_password_hash: str
):
    accounts_storage = UpgradableAccountsStorage(test_password_hash)
    auth = _auth(
        secondary_storage,
        accounts_storage,
        session_storage,
        password_hasher=HasherThatFailsToUpgrade(),
    )

    assert auth.authenticate(EMAIL, TEST_PASSWORD) is not None
    assert auth.authenticate(EMAIL, "wrong-password") is None

    assert accounts_storage.replacements == []


@pytest.fixture
def sqlmodel_storages(request: pytest.FixtureRequest):
    engine = make_sqlite_engine()
    request.addfinalizer(engine.dispose)
    accounts_storage = AccountsStore(session_factory=lambda: Session(engine))
    session_storage = SessionStore(session_factory=lambda: Session(engine))
    return engine, accounts_storage, session_storage


def _add_user(engine: Any, hashed_password: str, **fields: Any) -> int:
    with Session(engine) as db:
        user = User(
            email=EMAIL, email_verified=True, hashed_password=hashed_password, **fields
        )
        db.add(user)
        db.commit()
        assert user.id is not None
        return user.id


def _stored_user(engine: Any, user_id: int) -> User:
    with Session(engine) as db:
        return db.get_one(User, user_id)


def test_sqlmodel_storage_replaces_only_the_hash_it_still_stores(
    sqlmodel_storages,
):
    engine, accounts_storage, _ = sqlmodel_storages
    updated_at = datetime(2026, 1, 1)
    user_id = _add_user(engine, "old-hash", updated_at=updated_at)

    assert not accounts_storage.replace_password_hash(
        user_id, old_hash="another-hash", new_hash="new-hash"
    )
    assert not accounts_storage.replace_password_hash(
        user_id + 1, old_hash="old-hash", new_hash="new-hash"
    )
    assert _stored_user(engine, user_id).hashed_password == "old-hash"

    assert accounts_storage.replace_password_hash(
        str(user_id), old_hash="old-hash", new_hash="new-hash"
    )
    stored = _stored_user(engine, user_id)
    assert stored.hashed_password == "new-hash"
    # The password is the same, so the user did not change.
    assert stored.updated_at == updated_at


def test_sqlmodel_authenticate_upgrades_an_outdated_hash(
    sqlmodel_storages, secondary_storage, test_password_hash: str
):
    engine, accounts_storage, session_storage = sqlmodel_storages
    user_id = _add_user(engine, test_password_hash)
    auth = _auth(secondary_storage, accounts_storage, session_storage)

    assert auth.authenticate(EMAIL, TEST_PASSWORD) is not None

    stored = _stored_user(engine, user_id).hashed_password
    assert stored is not None
    assert stored.startswith("$argon2")


def test_password_changed_before_the_upgrade_keeps_its_hash(
    sqlmodel_storages, secondary_storage, test_password_hash: str
):
    engine, accounts_storage, session_storage = sqlmodel_storages
    user_id = _add_user(engine, test_password_hash)

    class HasherRacingAPasswordChange:
        """pwdlib, with the user's password changed once the old one matched."""

        def hash(self, password: str, /) -> str:
            return UPGRADING_HASHER.hash(password)

        def verify(self, password: str, hash: str, /) -> bool:
            return UPGRADING_HASHER.verify(password, hash)

        def verify_and_update(
            self, password: str, hash: str, /
        ) -> tuple[bool, str | None]:
            result = UPGRADING_HASHER.verify_and_update(password, hash)
            with Session(engine) as db:
                user = db.get_one(User, user_id)
                user.hashed_password = UPGRADING_HASHER.hash(NEW_PASSWORD)
                user.updated_at = datetime.now() + timedelta(seconds=1)
                db.add(user)
                db.commit()
            return result

    auth = _auth(
        secondary_storage,
        accounts_storage,
        session_storage,
        password_hasher=HasherRacingAPasswordChange(),
    )

    # The password matched when it was checked; the upgrade loses to the
    # change, which keeps its own hash.
    assert auth.authenticate(EMAIL, TEST_PASSWORD) is not None

    stored = _stored_user(engine, user_id).hashed_password
    assert stored is not None
    assert UPGRADING_HASHER.verify(NEW_PASSWORD, stored)
