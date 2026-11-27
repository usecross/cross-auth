from __future__ import annotations

import contextlib
import logging
import secrets
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Protocol

import bcrypt

from .exceptions import CrossAuthException

if TYPE_CHECKING:
    from ._login import AfterIssue
    from ._storage import AccountsStorage, SessionRecord, SessionStorage, User

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

        Accept Cross-Auth's dummy password, a random 64-character ASCII string
        it hashes once to verify for unknown users: while ``hash`` refuses it,
        every password check raises ``RuntimeError``.
        """
        ...

    def verify(self, password: str, hash: str, /) -> bool:
        """Return whether ``password`` matches the stored ``hash``.

        Return ``False`` only for a wrong password. For a hash you cannot read,
        raise, and before doing a verification's work, as bcrypt, pwdlib and
        passlib do: Cross-Auth counts it as no match and verifies its dummy
        hash instead, so the check still costs one verification. A hasher that
        returns ``False`` for such a hash answers faster for those users, and
        one that raises after the work answers slower.
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


@dataclass
class _HasherState:
    """What Cross-Auth keeps about a hasher it has checked passwords with."""

    # Kept alive here, so no other object can take its id.
    hasher: PasswordHasher
    dummy_hash: str
    # The verify errors already logged as a warning; later ones log at debug.
    warned: set[str] = field(default_factory=set)


# The state of each hasher, made the first time it checks a password and kept
# for the process. Keyed by id(), which works for unhashable hashers too.
# Applications use a hasher or two; past _MAX_HASHER_STATES the oldest entry is
# dropped, so making hashers on the fly cannot grow it.
_MAX_HASHER_STATES = 8
_hasher_states: dict[int, _HasherState] = {}
_hasher_states_lock = threading.Lock()


def _dummy_password() -> str:
    """Return a random password for a dummy hash.

    64 ASCII characters: long enough for common minimum lengths, and within
    the 72 bytes bcrypt reads.
    """
    return secrets.token_urlsafe(48)


def _hasher_state(password_hasher: PasswordHasher) -> _HasherState:
    """Return the state of ``password_hasher``, hashing its dummy on first use."""
    state = _hasher_states.get(id(password_hasher))
    if state is not None:
        return state
    # Under the lock, so concurrent first checks hash the dummy only once.
    with _hasher_states_lock:
        state = _hasher_states.get(id(password_hasher))
        if state is not None:
            return state
        try:
            dummy_hash = password_hasher.hash(_dummy_password())
        except Exception as error:
            # Raised for every check, whoever it is for, so the failure tells
            # no one which accounts exist.
            raise RuntimeError(
                "The password hasher refused Cross-Auth's dummy password, a "
                "random 64-character ASCII string; the configured hasher must "
                "accept it to check passwords"
            ) from error
        if len(_hasher_states) >= _MAX_HASHER_STATES:
            del _hasher_states[next(iter(_hasher_states))]
        state = _HasherState(password_hasher, dummy_hash)
        _hasher_states[id(password_hasher)] = state
    return state


def _dummy_hash(password_hasher: PasswordHasher) -> str:
    """Return a hash of a random password, made once by ``password_hasher``.

    Failed checks verify it to cost what a real check costs. That holds for
    stored hashes of the hasher's current scheme and settings: a hash from
    another scheme, or from a lower cost, verifies in its own time.
    """
    return _hasher_state(password_hasher).dummy_hash


def _check_password(
    password: str, password_hash: str, password_hasher: PasswordHasher
) -> bool:
    """Return whether ``password`` matches ``password_hash``.

    A hash the hasher cannot read, such as one another library produced, never
    matches: whatever ``verify`` raises counts as no match. It still costs one
    verification of the dummy hash, as unknown users and users without a
    password do.
    """
    try:
        return password_hasher.verify(password, password_hash)
    except Exception as error:
        _log_unreadable_hash(password_hasher, type(error).__name__)
    state = _hasher_state(password_hasher)
    # Verified for its time alone, so an error here changes nothing.
    with contextlib.suppress(Exception):
        password_hasher.verify(password, state.dummy_hash)
    return False


def _log_unreadable_hash(password_hasher: PasswordHasher, error: str) -> None:
    """Log that ``verify`` raised ``error``, a warning once per hasher.

    Only the error's type: its message could quote the hash. Without this, a
    misconfigured hasher would fail every sign-in in silence. Anyone can retry
    a sign-in for an account whose hash cannot be read, so each hasher warns
    once per error type and process, and logs later ones at debug level.
    """
    warned = _hasher_state(password_hasher).warned
    if error in warned:
        logger.debug(
            "The password hasher could not verify a password hash (%s), "
            "so it does not match",
            error,
        )
        return
    warned.add(error)
    logger.warning(
        "The password hasher could not verify a password hash (%s), so it "
        "does not match. Later ones like it log at debug level.",
        error,
    )


def _verify_password(
    user: User | None, password: str, password_hasher: PasswordHasher
) -> bool:
    """Verify a real or dummy hash, at the cost of one verification.

    Returns credential validity. The dummy hash is made before the user is
    looked at, so the first check pays for it whoever signs in, and a hasher
    that refuses the dummy password fails for every user alike.
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


class PasswordChanged(CrossAuthException):
    """A password sign-in whose password changed while it signed in.

    It answers as a wrong password does.
    """

    def __init__(self) -> None:
        super().__init__("invalid_grant", "Invalid username or password")


def unless_password_changed(
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage | None,
    *,
    user_id: str,
    password: str,
    checked_hash: str,
    password_hasher: PasswordHasher,
) -> AfterIssue:
    """End a password sign-in whose password changed while it signed in.

    ``checked_hash`` is the hash the sign-in checked ``password`` against. A
    password change stores the new hash before it revokes the user's
    sessions, as ``change_password`` does. Asked once the credential is
    stored, not before, this either finds the new hash, or the change comes
    later and its revocation finds this session. Asked before the write, a
    change in between would do neither. That holds when the session's write
    has committed by the time this reads the user.

    A changed hash still passes when ``password`` matches it, as when the same
    password is stored again with a new salt. Otherwise this revokes the
    session, if Cross Auth stored one, and raises ``PasswordChanged``. A
    credential a ``token_issuer`` minted is not revoked; it is never handed
    out.
    """

    def check(record: SessionRecord | None) -> None:
        user = accounts_storage.find_user_by_id(user_id)
        current_hash = None if user is None else user.hashed_password
        if current_hash == checked_hash:
            return
        if current_hash is not None and _check_password(
            password, current_hash, password_hasher
        ):
            return
        if record is not None and session_storage is not None:
            # Only this session: the change revoked the others.
            session_storage.revoke(record.id, revoked_at=datetime.now(tz=timezone.utc))
        raise PasswordChanged()

    return check
