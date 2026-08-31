from __future__ import annotations

from passlib.context import CryptContext

from ._storage import AccountsStorage, User

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Pre-computed dummy hash for constant-time password verification
# This prevents timing attacks that could enumerate valid users
DUMMY_PASSWORD_HASH = "$2b$12$K6qGJzUzL5H0yQKqVZKZFuJ9aZqZ5qH0yQKqVZKZFuJ9aZqZ5qH0y"  # noqa: S105


def _verify_password(user: User | None, password: str) -> bool:
    """Verify a real or dummy hash exactly once and return credential validity."""
    password_hash = user.hashed_password if user is not None else None
    valid = pwd_context.verify(
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
