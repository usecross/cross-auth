from __future__ import annotations

import contextlib
import logging
import secrets
import threading
from typing import TYPE_CHECKING, Protocol

import bcrypt

from .exceptions import CrossAuthException

if TYPE_CHECKING:
    from ._storage import AccountsStorage, User

logger = logging.getLogger(__name__)


class PasswordHasher(Protocol):
    """Hashes the passwords Cross-Auth stores and verifies the ones it checks.

    The parameters are positional-only, and Cross-Auth passes them by position,
    so a library's own names for them don't matter: pwdlib's ``PasswordHash``
    and passlib's ``CryptContext`` are hashers as they are.
    """

    def hash(self, password: str, /) -> str:
        """Return a hash of ``password``, to store in ``hashed_password``.

        Raise to refuse the password; nothing is stored. A
        ``CrossAuthException`` reaches the caller as it is, as
        ``password_too_long`` does from the default bcrypt hasher.
        """
        ...

    def verify(self, password: str, hash: str, /) -> bool:
        """Return whether ``password`` matches the stored ``hash``.

        Raise for a hash you cannot read, as bcrypt, pwdlib and passlib do.
        Cross-Auth counts it as no match, and spends one verification of a
        dummy hash so that the attempt takes as long as any other.
        """
        ...


# bcrypt is defined over the first 72 bytes of a password, so a stored hash
# encodes no more than that whatever the application hashed. Verification
# therefore compares the same 72 bytes; bcrypt 5 refuses longer input instead
# of ignoring the rest, which would lock those users out without making their
# hash any stronger. Guarding against long passwords belongs where they are
# hashed: BcryptPasswordHasher.hash rejects them.
_BCRYPT_MAX_PASSWORD_BYTES = 72


class BcryptPasswordHasher:
    """The default ``PasswordHasher``: bcrypt, with bcrypt's default cost."""

    def hash(self, password: str, /) -> str:
        """Return a bcrypt hash of ``password``.

        bcrypt reads only the first 72 bytes of a password, so a longer one
        raises ``CrossAuthException`` (``password_too_long``) instead of being
        cut short.
        """
        secret = password.encode("utf-8")
        if len(secret) > _BCRYPT_MAX_PASSWORD_BYTES:
            raise CrossAuthException(
                "password_too_long",
                f"The password is longer than {_BCRYPT_MAX_PASSWORD_BYTES} bytes",
            )
        return bcrypt.hashpw(secret, bcrypt.gensalt()).decode("ascii")

    def verify(self, password: str, hash: str, /) -> bool:
        """Return whether the first 72 bytes of ``password`` match ``hash``.

        A hash bcrypt cannot read, such as one another library produced,
        raises ``ValueError``.
        """
        secret = password.encode("utf-8")[:_BCRYPT_MAX_PASSWORD_BYTES]
        return bcrypt.checkpw(secret, hash.encode("utf-8"))


DEFAULT_PASSWORD_HASHER = BcryptPasswordHasher()


def hash_password(password: str) -> str:
    """Return a hash of ``password`` made by the default bcrypt hasher."""
    return DEFAULT_PASSWORD_HASHER.hash(password)


# The dummy hash of each hasher, made the first time it checks a password and
# kept for the process. Keyed by id(), which works for unhashable hashers too;
# each entry keeps its hasher alive, so no other object can take its id.
# Applications use a hasher or two; past _MAX_DUMMY_HASHES the oldest entry is
# dropped, so making hashers on the fly cannot grow it.
_MAX_DUMMY_HASHES = 8
_dummy_hashes: dict[int, tuple[PasswordHasher, str]] = {}
_dummy_hashes_lock = threading.Lock()


def _dummy_hash(password_hasher: PasswordHasher) -> str:
    """Return a hash of a random password, made once by ``password_hasher``.

    Failed checks verify it to take as long as a real check, which a hash made
    by the same hasher with its current settings does.
    """
    entry = _dummy_hashes.get(id(password_hasher))
    if entry is not None:
        return entry[1]
    dummy_hash = password_hasher.hash(secrets.token_urlsafe(16))
    with _dummy_hashes_lock:
        # Another thread may have made one meanwhile; keep the first.
        entry = _dummy_hashes.get(id(password_hasher))
        if entry is not None:
            return entry[1]
        if len(_dummy_hashes) >= _MAX_DUMMY_HASHES:
            del _dummy_hashes[next(iter(_dummy_hashes))]
        _dummy_hashes[id(password_hasher)] = (password_hasher, dummy_hash)
    return dummy_hash


def _check_password(
    password: str, password_hash: str, password_hasher: PasswordHasher
) -> bool:
    """Return whether ``password`` matches ``password_hash``.

    A hash the hasher cannot read, such as one another library produced, never
    matches: whatever ``verify`` raises counts as no match. It still costs one
    verification of the dummy hash, so that unknown users, users without a
    password and users with an unreadable hash take the same time.
    """
    try:
        return password_hasher.verify(password, password_hash)
    except Exception as error:
        # Only the error's type: its message could quote the hash. Without
        # this, a misconfigured hasher would fail every sign-in in silence.
        logger.warning(
            "The password hasher could not verify a password hash (%s), "
            "so it does not match",
            type(error).__name__,
        )
    dummy_hash = _dummy_hash(password_hasher)
    # Verified for its time alone, so an error here changes nothing.
    with contextlib.suppress(Exception):
        password_hasher.verify(password, dummy_hash)
    return False


def _verify_password(
    user: User | None, password: str, password_hasher: PasswordHasher
) -> bool:
    """Verify a real or dummy hash, at the cost of one verification.

    Returns credential validity. The dummy hash is made before the user is
    looked at, so the first check pays for it whoever signs in, and a hasher
    that cannot hash fails for every user alike.
    """
    dummy_hash = _dummy_hash(password_hasher)
    password_hash = user.hashed_password if user is not None else None
    valid = _check_password(
        password,
        password_hash if password_hash is not None else dummy_hash,
        password_hasher,
    )
    return password_hash is not None and valid


def authenticate(
    email: str,
    password: str,
    accounts_storage: AccountsStorage,
    *,
    password_hasher: PasswordHasher = DEFAULT_PASSWORD_HASHER,
) -> User | None:
    """Return the user ``email`` and ``password`` belong to, or ``None``.

    ``password_hasher`` verifies the user's stored hash; pass the one you give
    ``CrossAuth``, which defaults to bcrypt as this does.
    """
    user = accounts_storage.find_user_by_email(email)

    if not _verify_password(user, password, password_hasher):
        return None

    return user
