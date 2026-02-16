from __future__ import annotations

from passlib.context import CryptContext

from ._storage import AccountsStorage, User

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Pre-computed dummy hash for constant-time password verification
# This prevents timing attacks that could enumerate valid users
DUMMY_PASSWORD_HASH = "$2b$12$K6qGJzUzL5H0yQKqVZKZFuJ9aZqZ5qH0yQKqVZKZFuJ9aZqZ5qH0y"  # noqa: S105


def validate_password(user: User, password: str) -> bool:
    """Validate password in constant time.

    Returns False if the user has no password set, but still performs
    a dummy hash comparison to prevent timing attacks.
    """
    if user.hashed_password is None:
        pwd_context.verify(password, DUMMY_PASSWORD_HASH)
        return False
    return pwd_context.verify(password, user.hashed_password)


def authenticate(
    email: str,
    password: str,
    accounts_storage: AccountsStorage,
) -> User | None:
    user = accounts_storage.find_user_by_email(email)

    if user is not None:
        valid = validate_password(user, password)
    else:
        # Perform dummy hash verification for non-existent users
        # to maintain constant time and prevent user enumeration
        pwd_context.verify(password, DUMMY_PASSWORD_HASH)
        valid = False

    if not valid:
        return None

    return user
