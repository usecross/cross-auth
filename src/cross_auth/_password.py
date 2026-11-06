from __future__ import annotations

import bcrypt

from ._storage import AccountsStorage, User

# Pre-computed dummy hash for constant-time password verification
# This prevents timing attacks that could enumerate valid users
DUMMY_PASSWORD_HASH = "$2b$12$K6qGJzUzL5H0yQKqVZKZFuJ9aZqZ5qH0yQKqVZKZFuJ9aZqZ5qH0y"  # noqa: S105

# bcrypt is defined over the first 72 bytes of a password, so a stored hash
# encodes no more than that whatever the application hashed. Verification
# therefore compares the same 72 bytes; bcrypt 5 refuses longer input instead
# of ignoring the rest, which would lock those users out without making their
# hash any stronger. Guarding against long passwords belongs where they are
# hashed: reject them or pre-hash them at signup.
_BCRYPT_MAX_PASSWORD_BYTES = 72


def _check_password(password: str, password_hash: str) -> bool:
    """Return whether ``password`` matches the bcrypt ``password_hash``.

    A hash bcrypt cannot read, such as one another library produced, never
    matches; it still costs one bcrypt comparison so that unknown users, users
    without a password and users with a foreign hash take the same time.
    """
    secret = password.encode("utf-8")[:_BCRYPT_MAX_PASSWORD_BYTES]
    try:
        return bcrypt.checkpw(secret, password_hash.encode("utf-8"))
    except ValueError:
        bcrypt.checkpw(secret, DUMMY_PASSWORD_HASH.encode("ascii"))
        return False


def _verify_password(user: User | None, password: str) -> bool:
    """Verify a real or dummy hash exactly once and return credential validity."""
    password_hash = user.hashed_password if user is not None else None
    valid = _check_password(
        password,
        password_hash if password_hash is not None else DUMMY_PASSWORD_HASH,
    )
    return password_hash is not None and valid


def authenticate(
    email: str,
    password: str,
    accounts_storage: AccountsStorage,
) -> User | None:
    user = accounts_storage.find_user_by_email(email)

    if not _verify_password(user, password):
        return None

    return user
