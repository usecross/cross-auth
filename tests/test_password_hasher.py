"""The password hasher verifies every password core checks.

Unknown users, users without a password and users whose hash the hasher cannot
read each cost one verification, of a dummy hash the hasher makes once, on
first use. A hash the hasher cannot read never matches and never raises.
"""

import hashlib
import logging
from dataclasses import dataclass, field
from typing import cast
from unittest.mock import Mock

import pytest
from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher

from cross_auth import BcryptPasswordHasher, Context, PasswordHasher
from cross_auth._password import (
    _MAX_DUMMY_HASHES,
    DEFAULT_PASSWORD_HASHER,
    _dummy_hash,
    _dummy_hashes,
    _verify_password,
)
from cross_auth._storage import AccountsStorage, SecondaryStorage, User

from .conftest import TEST_PASSWORD

# Cheap parameters: the tests only need real argon2 hashes.
ARGON2 = Argon2Hasher(time_cost=1, memory_cost=1024)
# A bcrypt hash, which the hashers below cannot read.
FOREIGN_HASH = "$2b$04$KN0eWzzk9ntVk3UCTZQW0eM9d1SqGzjUjPAPwlCRm3JIi5aVaQ2bq"


def _digest(password: str) -> str:
    return "sha256$" + hashlib.sha256(password.encode()).hexdigest()


@dataclass
class RecordingHasher:
    """Hashes to ``sha256$<hex>`` and records the hashes it verifies.

    A dataclass compares by value, so it is unhashable, as a hasher may be.
    """

    hashed: int = 0
    verified: list[str] = field(default_factory=list)

    def hash(self, password: str, /) -> str:
        self.hashed += 1
        return _digest(password)

    def verify(self, password: str, hash: str, /) -> bool:
        self.verified.append(hash)
        if not hash.startswith("sha256$"):
            raise ValueError(f"Not a hash this hasher made: {hash}")
        return hash == _digest(password)


def _user(hashed_password: str | None) -> User:
    return cast(User, Mock(hashed_password=hashed_password))


def _context(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    password_hasher: PasswordHasher | None = None,
) -> Context:
    return Context(
        secondary_storage=secondary_storage,
        accounts_storage=accounts_storage,
        get_user_from_request=lambda request: None,
        password_hasher=password_hasher,
    )


def test_pwdlib_is_a_password_hasher_as_it_is():
    # ty checks the assignment against the protocol.
    hasher: PasswordHasher = PasswordHash((ARGON2,))
    hashed_password = hasher.hash(TEST_PASSWORD)
    user = _user(hashed_password)

    assert hashed_password.startswith("$argon2id$")
    assert _verify_password(user, TEST_PASSWORD, hasher) is True
    assert _verify_password(user, "wrong password", hasher) is False


def test_bcrypt_is_the_default(secondary_storage, accounts_storage):
    context = _context(secondary_storage, accounts_storage)

    assert context.password_hasher is DEFAULT_PASSWORD_HASHER
    assert isinstance(context.password_hasher, BcryptPasswordHasher)


def test_the_context_keeps_the_hasher_without_hashing(
    secondary_storage, accounts_storage
):
    hasher = RecordingHasher()

    context = _context(secondary_storage, accounts_storage, hasher)

    assert context.password_hasher is hasher
    # The dummy hash is made on first use, not with the context.
    assert hasher.hashed == 0


@pytest.mark.parametrize(
    "case", ["correct", "incorrect", "unknown", "passwordless", "unreadable"]
)
def test_each_check_verifies_one_hash_the_hasher_can_read(case: str):
    hasher = RecordingHasher()
    dummy_hash = _dummy_hash(hasher)
    stored = _digest(TEST_PASSWORD)
    user, password, verified, valid = {
        "correct": (_user(stored), TEST_PASSWORD, stored, True),
        "incorrect": (_user(stored), "wrong password", stored, False),
        "unknown": (None, TEST_PASSWORD, dummy_hash, False),
        "passwordless": (_user(None), TEST_PASSWORD, dummy_hash, False),
        "unreadable": (_user(FOREIGN_HASH), TEST_PASSWORD, dummy_hash, False),
    }[case]

    assert _verify_password(user, password, hasher) is valid

    # A hash the hasher cannot read fails without the work of a verification,
    # so the dummy hash is verified after it.
    readable = [hash for hash in hasher.verified if hash.startswith("sha256$")]
    assert readable == [verified]


def test_the_dummy_hash_is_made_once_by_the_hasher():
    hasher = RecordingHasher()

    _verify_password(None, TEST_PASSWORD, hasher)
    _verify_password(None, "another password", hasher)

    assert hasher.hashed == 1
    assert hasher.verified == [_dummy_hash(hasher)] * 2


def test_the_dummy_hash_is_made_before_the_user_is_looked_at():
    hasher = RecordingHasher()

    _verify_password(_user(_digest(TEST_PASSWORD)), TEST_PASSWORD, hasher)

    # The first check pays for the dummy hash whoever it is for.
    assert hasher.hashed == 1


def test_a_hasher_that_cannot_hash_fails_for_every_user_alike():
    class BrokenHasher(RecordingHasher):
        def hash(self, password: str, /) -> str:
            raise RuntimeError("misconfigured")

    hasher = BrokenHasher()

    with pytest.raises(RuntimeError):
        _verify_password(None, TEST_PASSWORD, hasher)
    with pytest.raises(RuntimeError):
        _verify_password(_user(_digest(TEST_PASSWORD)), TEST_PASSWORD, hasher)


def test_an_unreadable_hash_logs_only_the_error_type(
    caplog: pytest.LogCaptureFixture,
):
    hasher = RecordingHasher()

    with caplog.at_level(logging.WARNING, logger="cross_auth._password"):
        valid = _verify_password(_user(FOREIGN_HASH), TEST_PASSWORD, hasher)

    assert valid is False
    assert [record.getMessage() for record in caplog.records] == [
        "The password hasher could not verify a password hash (ValueError), "
        "so it does not match"
    ]
    assert FOREIGN_HASH not in caplog.text
    assert TEST_PASSWORD not in caplog.text


def test_pwdlib_does_not_match_a_hash_it_cannot_identify():
    # PasswordHash raises UnknownHashError, which is not a ValueError.
    hasher = PasswordHash((ARGON2,))

    assert _verify_password(_user(FOREIGN_HASH), TEST_PASSWORD, hasher) is False
    assert _verify_password(_user("plain text"), TEST_PASSWORD, hasher) is False


def test_an_error_verifying_the_dummy_hash_is_not_raised():
    class RefusingHasher(RecordingHasher):
        def verify(self, password: str, hash: str, /) -> bool:
            super().verify(password, hash)
            raise ValueError("The password is too long")

    hasher = RefusingHasher()

    assert _verify_password(None, "p" * 80, hasher) is False
    assert _verify_password(_user(_digest("p" * 80)), "p" * 80, hasher) is False


def test_dummy_hashes_are_kept_for_a_few_hashers_only():
    hashers = [RecordingHasher() for _ in range(_MAX_DUMMY_HASHES + 2)]

    for hasher in hashers:
        _verify_password(None, TEST_PASSWORD, hasher)

    assert len(_dummy_hashes) == _MAX_DUMMY_HASHES
    assert id(hashers[-1]) in _dummy_hashes
    assert id(hashers[0]) not in _dummy_hashes
