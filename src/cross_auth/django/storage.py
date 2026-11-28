"""Django ORM implementations of Cross Auth's storage protocols.

Each storage captures its authoritative write database at construction; reads,
transactions and commit callbacks use that alias even if routing later changes.
Multi-statement mutations run in ``transaction.atomic``, committing before
returning in autocommit views. Inside an application's atomic block on that
alias, writes join it and ``on_commit`` waits for its outermost commit.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from datetime import timezone as dt_timezone
from typing import TYPE_CHECKING, Any, TypedDict

from django.contrib.auth import get_user_model
from django.contrib.sessions.backends.base import VALID_KEY_CHARS
from django.core.exceptions import (
    ImproperlyConfigured,
    ObjectDoesNotExist,
    ValidationError,
)
from django.db import DatabaseError, IntegrityError, router, transaction
from django.db.models import Case, F, Q, Value, When
from django.utils import timezone
from django.utils.crypto import get_random_string

from cross_auth._storage import (
    CommitCallback,
    DisconnectResult,
    SessionListOrder,
    SessionStatus,
    SocialAccountCreate,
    UserCreate,
    session_status,
)
from cross_auth._storage import User as CrossAuthUser
from cross_auth.exceptions import CrossAuthException, InvalidCursorError
from cross_auth.storage._cursor import decode_cursor, encode_cursor

from ._session_management import end_sessions
from .conf import get_settings
from .models import ExpiringValue, MFAFactor, RecoveryCode, Session, SocialAccount

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from django.contrib.auth.base_user import AbstractBaseUser
    from django.db.models import Model, QuerySet


class DjangoUser:
    """Cross Auth's view of a native Django user.

    Core reads a few user values under its own names. Django has no
    verified-email flag, so ``email_verified`` is always False; verified
    provider emails stay on each ``SocialAccount``. The password hash is never
    exposed.
    """

    __slots__ = ("native", "_password_login")

    def __init__(self, native: AbstractBaseUser, *, password_login: bool) -> None:
        self.native = native
        self._password_login = password_login

    @property
    def id(self) -> Any:
        return self.native.pk

    @property
    def email(self) -> str | None:
        # EMAIL_FIELD is configured per user model.
        value = getattr(self.native, self.native.get_email_field_name(), None)
        return value or None

    @property
    def email_verified(self) -> bool:
        return False

    @property
    def hashed_password(self) -> str | None:
        return None

    @property
    def has_usable_password(self) -> bool:
        return self._password_login and self.native.has_usable_password()


_NO_MATCH = object()


def _coerce_pk(model: type[Model], value: object) -> object:
    """Convert an ID from a URL or stored state, or return ``_NO_MATCH``."""
    try:
        return model._meta.pk.to_python(value)
    except (TypeError, ValueError, ValidationError):
        return _NO_MATCH


class _Credentials(TypedDict):
    """The SocialAccount fields that hold a provider's credentials."""

    encrypted_access_token: str | None
    encrypted_refresh_token: str | None
    access_token_expires_at: datetime | None
    refresh_token_expires_at: datetime | None
    scope: str | None


def _utc(value: datetime | None) -> datetime | None:
    """A naive time from a hook counts as UTC, as in the SQLModel storage.

    Django would otherwise read it in ``TIME_ZONE`` and store another instant.
    """
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=dt_timezone.utc)


def _credentials(
    *,
    access_token: str | None,
    refresh_token: str | None,
    access_token_expires_at: datetime | None,
    refresh_token_expires_at: datetime | None,
    scope: str | None,
) -> _Credentials:
    """The credential fields to write, encrypted.

    Without ``CROSS_AUTH["PROVIDER_TOKENS"]`` they are all empty, so turning
    the setting off clears a row's credentials the next time it is written.
    """
    tokens = get_settings().provider_tokens
    if tokens is None:
        access_token = refresh_token = scope = None
        access_token_expires_at = refresh_token_expires_at = None

    def encrypt(value: str | None) -> str | None:
        if value is None or tokens is None:
            return None
        encrypted = tokens.encrypt(value)
        if not isinstance(encrypted, str):
            raise TypeError("CROSS_AUTH['PROVIDER_TOKENS']['encrypt'] must return str")
        return encrypted

    return _Credentials(
        encrypted_access_token=encrypt(access_token),
        encrypted_refresh_token=encrypt(refresh_token),
        access_token_expires_at=_utc(access_token_expires_at),
        refresh_token_expires_at=_utc(refresh_token_expires_at),
        scope=scope,
    )


def _check_no_extra_fields(extra_fields: Mapping[str, Any] | None) -> None:
    if extra_fields:
        raise TypeError(
            "The Django SocialAccount model has no extra fields; got "
            f"{sorted(extra_fields)!r} from a social_account hook"
        )


class DjangoAccountsStorage:
    """Stores identities in ``cross_auth.SocialAccount`` next to native users."""

    def __init__(self) -> None:
        self._user_model = get_user_model()
        self.alias = router.db_for_write(self._user_model)
        if router.db_for_write(SocialAccount) != self.alias:
            raise ImproperlyConfigured(
                "Cross Auth users and SocialAccount must share a write database"
            )

    def _users(self) -> QuerySet[AbstractBaseUser]:
        return self._user_model._default_manager.using(self.alias)

    def _accounts(self) -> QuerySet[SocialAccount]:
        return SocialAccount.objects.using(self.alias)

    def _wrap(self, native: AbstractBaseUser) -> DjangoUser:
        return DjangoUser(native, password_login=get_settings().password_login)

    def on_commit(self, callback: CommitCallback) -> None:
        transaction.on_commit(callback, using=self.alias, robust=False)

    def find_user_by_email(self, email: str) -> DjangoUser | None:
        email_field = self._user_model.get_email_field_name()
        matches = list(self._users().filter(**{f"{email_field}__iexact": email})[:2])
        if len(matches) > 1:
            raise CrossAuthException(
                "account_not_linked",
                error_description=(
                    "Several accounts use this email. Sign in and connect the "
                    "provider from your account."
                ),
            )
        return self._wrap(matches[0]) if matches else None

    def find_user_by_id(self, id: Any) -> DjangoUser | None:
        pk = _coerce_pk(self._user_model, id)
        if pk is _NO_MATCH:
            return None
        native = self._users().filter(pk=pk).first()
        return self._wrap(native) if native is not None else None

    def find_social_account(
        self,
        *,
        provider: str,
        provider_user_id: str,
        user_id: Any | None = None,
        is_login_method: bool | None = None,
    ) -> SocialAccount | None:
        accounts = self._accounts().filter(
            provider=provider, provider_user_id=provider_user_id
        )
        if user_id is not None:
            pk = _coerce_pk(self._user_model, user_id)
            if pk is _NO_MATCH:
                return None
            accounts = accounts.filter(user_id=pk)
        if is_login_method is not None:
            accounts = accounts.filter(is_login_method=is_login_method)
        # The unique identity constraint allows at most one row.
        return accounts.first()

    def has_social_account(self, *, provider: str, provider_user_id: str) -> bool:
        return (
            self._accounts()
            .filter(provider=provider, provider_user_id=provider_user_id)
            .exists()
        )

    def find_social_account_by_id(self, social_account_id: Any) -> SocialAccount | None:
        pk = _coerce_pk(SocialAccount, social_account_id)
        if pk is _NO_MATCH:
            return None
        return self._accounts().filter(pk=pk).first()

    def list_social_accounts(self, *, user_id: Any) -> list[SocialAccount]:
        pk = _coerce_pk(self._user_model, user_id)
        if pk is _NO_MATCH:
            return []
        return list(self._accounts().filter(user_id=pk).order_by("pk"))

    def create_user_with_identity(
        self,
        *,
        user: UserCreate,
        identity: Callable[[CrossAuthUser], SocialAccountCreate],
    ) -> tuple[DjangoUser, SocialAccount]:
        """Create the user, the rows its factory writes, and the identity.

        All of them commit together or not at all. When a concurrent sign-in
        stored the same identity, or a native user with this email, first, the
        database rejects this one, everything rolls back and the conflict is a
        ``CrossAuthException``. Other integrity errors propagate.
        """
        factory = get_settings().create_user
        data: SocialAccountCreate | None = None
        try:
            with transaction.atomic(using=self.alias):
                native = factory(
                    email=user["email"],
                    user_info=user["user_info"],
                    extra_fields=user["extra_fields"] or {},
                    using=self.alias,
                )
                if (
                    not isinstance(native, self._user_model)
                    or native._state.adding
                    or native._state.db != self.alias
                ):
                    raise ImproperlyConfigured(
                        "CREATE_USER must return a saved AUTH_USER_MODEL on "
                        f"database {self.alias!r}; use the supplied using alias for "
                        "all factory writes"
                    )
                created = self._wrap(native)
                data = identity(created)
                if _coerce_pk(self._user_model, data["user_id"]) != native.pk:
                    raise ValueError("Initial identity must belong to the new user")
                _check_no_extra_fields(data["extra_fields"])
                account = self._accounts().create(
                    user_id=native.pk,
                    provider=data["provider"],
                    provider_user_id=data["provider_user_id"],
                    provider_email=data["provider_email"],
                    provider_email_verified=data["provider_email_verified"],
                    is_login_method=data["is_login_method"],
                    **_credentials(
                        access_token=data["access_token"],
                        refresh_token=data["refresh_token"],
                        access_token_expires_at=data["access_token_expires_at"],
                        refresh_token_expires_at=data["refresh_token_expires_at"],
                        scope=data["scope"],
                    ),
                )
        except IntegrityError as error:
            if data is not None and self.has_social_account(
                provider=data["provider"], provider_user_id=data["provider_user_id"]
            ):
                raise CrossAuthException("account_already_linked") from error
            # Core signs up only after finding no user with this email, so one
            # existing now was committed by a concurrent sign-up. Leave it to
            # the next attempt, which signs in or reports the unlinked email.
            if self.find_user_by_email(user["email"]) is not None:
                raise CrossAuthException(
                    "account_not_linked",
                    error_description=(
                        "Another sign-in created an account with this email at "
                        "the same time. Try signing in again."
                    ),
                ) from error
            raise
        return created, account

    def create_social_account(
        self,
        *,
        user_id: Any,
        provider: str,
        provider_user_id: str,
        access_token: str | None,
        refresh_token: str | None,
        access_token_expires_at: datetime | None,
        refresh_token_expires_at: datetime | None,
        scope: str | None,
        user_info: dict[str, Any],
        provider_email: str | None,
        provider_email_verified: bool | None,
        is_login_method: bool,
        extra_fields: Mapping[str, Any] | None = None,
    ) -> SocialAccount:
        _check_no_extra_fields(extra_fields)
        pk = _coerce_pk(self._user_model, user_id)
        if pk is _NO_MATCH:
            raise ValueError(f"Invalid user ID {user_id!r}")
        try:
            with transaction.atomic(using=self.alias):
                return self._accounts().create(
                    user_id=pk,
                    provider=provider,
                    provider_user_id=provider_user_id,
                    provider_email=provider_email,
                    provider_email_verified=provider_email_verified,
                    is_login_method=is_login_method,
                    **_credentials(
                        access_token=access_token,
                        refresh_token=refresh_token,
                        access_token_expires_at=access_token_expires_at,
                        refresh_token_expires_at=refresh_token_expires_at,
                        scope=scope,
                    ),
                )
        except IntegrityError as error:
            existing = self.find_social_account(
                provider=provider, provider_user_id=provider_user_id, user_id=pk
            )
            if existing is None:
                if self.has_social_account(
                    provider=provider, provider_user_id=provider_user_id
                ):
                    raise CrossAuthException("account_already_linked") from error
                raise
            if is_login_method and not existing.is_login_method:
                raise CrossAuthException("account_already_linked") from error
            return existing

    def update_social_account(
        self,
        social_account_id: Any,
        *,
        access_token: str | None,
        refresh_token: str | None,
        access_token_expires_at: datetime | None,
        refresh_token_expires_at: datetime | None,
        scope: str | None,
        user_info: dict[str, Any],
        provider_email: str | None,
        provider_email_verified: bool | None,
        enable_login: bool = False,
        extra_fields: Mapping[str, Any] | None = None,
    ) -> SocialAccount:
        _check_no_extra_fields(extra_fields)
        pk = _coerce_pk(SocialAccount, social_account_id)
        values: dict[str, Any] = {
            "provider_email": provider_email,
            "provider_email_verified": provider_email_verified,
            "updated_at": timezone.now(),
            **_credentials(
                access_token=access_token,
                refresh_token=refresh_token,
                access_token_expires_at=access_token_expires_at,
                refresh_token_expires_at=refresh_token_expires_at,
                scope=scope,
            ),
        }
        # Exclusive identity ownership means promotion cannot create a second
        # login owner.
        if enable_login:
            values["is_login_method"] = True
        # One UPDATE statement: SQLite cannot upgrade a read transaction to a
        # write while another connection is writing.
        if pk is _NO_MATCH or self._accounts().filter(pk=pk).update(**values) == 0:
            raise ValueError(f"Social account {social_account_id!r} does not exist")
        return self._accounts().get(pk=pk)

    def disconnect_social_account(
        self,
        *,
        user_id: Any,
        provider: str,
        social_account_id: Any,
    ) -> DisconnectResult:
        """Remove an owned identity unless it is the user's last way to sign in.

        A no-op update of the user row is the first statement, so same-user
        disconnects serialize: PostgreSQL holds the row lock until commit and
        SQLite takes its write lock before reading anything that could go
        stale. ``select_for_update`` alone is a no-op on SQLite.
        """
        user_model = self._user_model
        user_pk = _coerce_pk(user_model, user_id)
        account_pk = _coerce_pk(SocialAccount, social_account_id)
        if user_pk is _NO_MATCH or account_pk is _NO_MATCH:
            return "not_found"

        pk_name = user_model._meta.pk.name
        with transaction.atomic(using=self.alias):
            users = self._users().filter(pk=user_pk)
            if users.update(**{pk_name: F(pk_name)}) == 0:
                return "not_found"
            native = users.first()
            account = (
                self._accounts()
                .filter(pk=account_pk, user_id=user_pk, provider=provider)
                .first()
            )
            if native is None or account is None:
                return "not_found"

            if account.is_login_method and not self._wrap(native).has_usable_password:
                has_alternative = (
                    self._accounts()
                    .filter(user_id=user_pk, is_login_method=True)
                    .exclude(pk=account.pk)
                    .exists()
                )
                if not has_alternative:
                    return "last_login_method"

            account.delete()
        return "disconnected"


class DjangoSecondaryStorage:
    """Expiring key/value storage on the ``cross_auth.ExpiringValue`` table.

    ``pop`` locks before reading so consumption also serializes with ``set``.
    Expired rows are logically absent; schedule ``clear_expired`` separately
    to reclaim them instead of scanning the table on each OAuth write.
    """

    def __init__(self) -> None:
        self.alias = router.db_for_write(ExpiringValue)

    def _values(self) -> QuerySet[ExpiringValue]:
        return ExpiringValue.objects.using(self.alias)

    def _live(self, key: str) -> QuerySet[ExpiringValue]:
        return self._values().filter(
            Q(expires_at__isnull=True) | Q(expires_at__gt=timezone.now()), key=key
        )

    def set(self, key: str, value: str, ttl: int | None = None) -> None:
        now = timezone.now()
        expires_at = now + timedelta(seconds=ttl) if ttl is not None else None
        # Write first rather than read-then-write, which SQLite cannot upgrade
        # while another connection writes. Concurrent sets: the last one wins.
        values = {"value": value, "expires_at": expires_at}
        if self._values().filter(key=key).update(**values):
            return
        try:
            with transaction.atomic(using=self.alias):
                self._values().create(key=key, **values)
        except IntegrityError:
            self._values().filter(key=key).update(**values)

    def get(self, key: str) -> str | None:
        return self._live(key).values_list("value", flat=True).first()

    def delete(self, key: str) -> None:
        self._values().filter(key=key).delete()

    def pop(self, key: str) -> str | None:
        # A write-first boundary works on both PostgreSQL (row lock) and
        # SQLite (database write lock); select_for_update is inert on SQLite.
        # Include expired rows so a concurrent set cannot replace one between
        # our read and delete. Missing keys can linearize at the UPDATE.
        with transaction.atomic(using=self.alias):
            rows = self._values().filter(key=key)
            if not rows.update(value=F("value")):
                return None
            row = rows.get()
            rows.delete()
            if row.expires_at is not None and row.expires_at <= timezone.now():
                return None
            return row.value

    def clear_expired(self) -> int:
        """Delete expired values; call from scheduled maintenance, not requests."""
        deleted, _ = self._values().filter(expires_at__lte=timezone.now()).delete()
        return deleted


@dataclass(frozen=True)
class DjangoSessionRecord:
    """A user's session, as Cross Auth's ``SessionRecord`` reads it.

    It is a bearer token's session or a browser's; ``client_id`` is ``None``
    for a browser's. ``id`` is the row's ``public_id``, which is safe to show
    and to send back; the row's session key and token hash are not part of
    the record. ``native`` is the row itself, as it was when the record was
    read.
    """

    native: Session

    @property
    def id(self) -> uuid.UUID:
        return self.native.public_id

    @property
    def user_id(self) -> Any:
        return self.native.user_id

    @property
    def created_at(self) -> datetime:
        return self.native.created_at

    @property
    def updated_at(self) -> datetime:
        return self.native.updated_at

    @property
    def expires_at(self) -> datetime:
        return self.native.expire_date

    @property
    def last_active_at(self) -> datetime | None:
        return self.native.last_activity

    @property
    def revoked_at(self) -> datetime | None:
        return self.native.revoked_at

    @property
    def client_id(self) -> str | None:
        return self.native.client_id

    @property
    def client_name(self) -> str | None:
        return self.native.client_name

    @property
    def user_agent(self) -> str | None:
        return self.native.user_agent

    @property
    def ip(self) -> str | None:
        return self.native.ip

    @property
    def login_method(self) -> str | None:
        return self.native.login_method

    @property
    def mfa_method(self) -> str | None:
        return self.native.mfa_method

    @property
    def status(self) -> SessionStatus:
        return session_status(self)


@dataclass(frozen=True)
class DjangoSessionList:
    records: list[DjangoSessionRecord]
    next_cursor: str | None


# order_by -> (model field, descending?)
_SESSION_ORDER: dict[SessionListOrder, tuple[str, bool]] = {
    "updated_at_desc": ("updated_at", True),
    "updated_at_asc": ("updated_at", False),
    "created_at_desc": ("created_at", True),
    "created_at_asc": ("created_at", False),
    "expires_at_desc": ("expire_date", True),
    "expires_at_asc": ("expire_date", False),
}


def _public_id(session_id: object) -> uuid.UUID | None:
    if isinstance(session_id, uuid.UUID):
        return session_id
    try:
        return uuid.UUID(str(session_id))
    except ValueError:
        return None


class DjangoSessionStorage:
    """Implements ``cross_auth.SessionStorage`` on ``cross_auth.django.models.Session``.

    It creates, finds, extends and records the use of the sessions of bearer
    tokens: the rows with a ``token_hash``. With
    ``SESSION_ENGINE = "cross_auth.django.sessions"`` the signed-in browser
    sessions share the table, and this storage lists and revokes those too,
    so a user's sessions are one list whichever way they signed in. Django's
    session store still creates and saves them. A session is named by its
    ``public_id``.

    A browser session counts as active here until Django ends it. One that a
    password change ended is only marked the next time its browser sends a
    request, so until then it is still listed as active.

    A revoked session keeps its row, with ``revoked_at`` set, until it would
    have expired. ``clearsessions`` then deletes it if ``SESSION_ENGINE`` is
    ``cross_auth.django.sessions``; with another engine, call
    ``clear_expired`` from scheduled maintenance.

    A session row points to its user, so both must be written to the same
    database; construction fails otherwise.
    """

    def __init__(self) -> None:
        user_model = get_user_model()
        self.alias = router.db_for_write(Session)
        if router.db_for_write(user_model) != self.alias:
            # Found out here, not when a token's row cannot be inserted: by
            # then the client's one-time code is used up.
            raise ImproperlyConfigured(
                "Cross Auth users and Session must share a write database"
            )
        self._user_pk = user_model._meta.pk

    def _sessions(self) -> QuerySet[Session]:
        """Every session of a user: bearer tokens' and signed-in browsers'."""
        # Read from the database that writes them: a replica could still show
        # a session that was just revoked.
        return Session.objects.using(self.alias).filter(user__isnull=False)

    def _tokens(self) -> QuerySet[Session]:
        """The sessions this storage issues, extends and records the use of.

        Django's session store does that for browser sessions.
        """
        return self._sessions().filter(token_hash__isnull=False)

    def _user_sessions(self, user_id: object) -> QuerySet[Session]:
        try:
            user_pk = self._user_pk.to_python(user_id)
        except ValidationError:
            return self._sessions().none()

        return self._sessions().filter(user_id=user_pk)

    def _one(self, session_id: object) -> QuerySet[Session]:
        public_id = _public_id(session_id)
        if public_id is None:
            return self._sessions().none()

        return self._sessions().filter(public_id=public_id)

    def _one_token(self, session_id: object) -> QuerySet[Session]:
        return self._one(session_id).filter(token_hash__isnull=False)

    def on_commit(self, callback: CommitCallback) -> None:
        transaction.on_commit(callback, using=self.alias, robust=False)

    def create(
        self,
        *,
        token_hash: str,
        user_id: object,
        created_at: datetime,
        updated_at: datetime,
        expires_at: datetime,
        client_id: str | None = None,
        client_name: str | None = None,
        user_agent: str | None = None,
        ip: str | None = None,
        last_active_at: datetime | None = None,
        login_method: str | None = None,
        mfa_method: str | None = None,
    ) -> DjangoSessionRecord:
        store = Session.get_session_store_class()()
        session = Session(
            # Django requires both. The key is random and given to nobody,
            # and the data is an empty session, as a session store reads it.
            session_key=get_random_string(32, VALID_KEY_CHARS),
            session_data=store.encode({}),
            expire_date=expires_at,
            user_id=self._user_pk.to_python(user_id),
            token_hash=token_hash,
            created_at=created_at,
            updated_at=updated_at,
            last_activity=last_active_at or created_at,
            client_id=client_id,
            client_name=client_name,
            user_agent=user_agent,
            ip=ip,
            login_method=login_method,
            mfa_method=mfa_method,
        )
        session.save(force_insert=True, using=self.alias)

        return DjangoSessionRecord(session)

    def get(self, *, token_hash: str, now: datetime) -> DjangoSessionRecord | None:
        session = (
            self._tokens()
            # A session is active up to and including its expiry instant,
            # like cross_auth.session_status.
            .filter(
                token_hash=token_hash, revoked_at__isnull=True, expire_date__gte=now
            )
            .first()
        )
        if session is None:
            return None
        if session.ip is not None and not get_settings().session_store_ip:
            self._clear_ip(session)

        return DjangoSessionRecord(session)

    def _clear_ip(self, session: Session) -> None:
        """Forget the IP of a session issued while sessions still stored one.

        Like a browser session, a token's session loses it the next time it
        is used once ``CROSS_AUTH["SESSION_STORE_IP"]`` is off. Best-effort,
        as recording activity is: a database error is logged, not raised.
        """
        try:
            with transaction.atomic(using=self.alias):
                self._one_token(session.public_id).update(ip=None)
        except DatabaseError:
            logger.warning("Could not clear a session's IP", exc_info=True)
            return
        session.ip = None

    def get_any(self, session_id: object) -> DjangoSessionRecord | None:
        session = self._one(session_id).first()

        return None if session is None else DjangoSessionRecord(session)

    def list_for_user(
        self,
        user_id: object,
        *,
        now: datetime,
        status: SessionStatus | None = None,
        order_by: SessionListOrder = "updated_at_desc",
        limit: int = 50,
        cursor: str | None = None,
    ) -> DjangoSessionList:
        if limit < 1:
            raise ValueError("limit must be >= 1")
        try:
            field, descending = _SESSION_ORDER[order_by]
        except KeyError:
            raise ValueError(f"Unsupported order_by: {order_by!r}") from None

        sessions = self._user_sessions(user_id)
        if status == "revoked":
            sessions = sessions.filter(revoked_at__isnull=False)
        elif status == "active":
            sessions = sessions.filter(revoked_at__isnull=True, expire_date__gte=now)
        elif status == "expired":
            sessions = sessions.filter(revoked_at__isnull=True, expire_date__lt=now)

        if cursor is not None:
            decoded = decode_cursor(cursor)
            if decoded.order_by != order_by:
                raise InvalidCursorError(
                    f"Cursor was created with order_by={decoded.order_by!r}, "
                    f"not {order_by!r}"
                )
            if not isinstance(decoded.row_id, uuid.UUID):
                raise InvalidCursorError("Invalid session pagination cursor")
            beyond = "lt" if descending else "gt"
            sessions = sessions.filter(
                Q(**{f"{field}__{beyond}": decoded.value})
                | Q(**{field: decoded.value, f"public_id__{beyond}": decoded.row_id})
            )

        prefix = "-" if descending else ""
        rows = list(
            sessions.order_by(f"{prefix}{field}", f"{prefix}public_id")[: limit + 1]
        )
        records = [DjangoSessionRecord(session) for session in rows[:limit]]
        next_cursor = None
        if len(rows) > limit:
            last = rows[limit - 1]
            order_value = {
                "updated_at": last.updated_at,
                "created_at": last.created_at,
                "expire_date": last.expire_date,
            }[field]
            next_cursor = encode_cursor(order_by, order_value, last.public_id)

        return DjangoSessionList(records=records, next_cursor=next_cursor)

    def refresh(
        self,
        session_id: object,
        *,
        updated_at: datetime,
        expires_at: datetime,
        last_active_at: datetime | None = None,
    ) -> DjangoSessionRecord | None:
        active = self._one_token(session_id).filter(
            revoked_at__isnull=True, expire_date__gte=updated_at
        )
        values: dict[str, object] = {
            "updated_at": updated_at,
            "expire_date": expires_at,
        }
        if last_active_at is not None:
            # Keep a later use that another request recorded meanwhile.
            values["last_activity"] = Case(
                When(last_activity__lt=last_active_at, then=Value(last_active_at)),
                default=F("last_activity"),
            )

        with transaction.atomic(using=self.alias):
            # Only move forward: a request that read the session before a
            # newer refresh committed must not roll its expiry back.
            if active.filter(updated_at__lt=updated_at).update(**values):
                session = self._one_token(session_id).first()
            else:
                # Either the session stopped being active, or a newer refresh
                # already moved it past updated_at; return it in the latter
                # case.
                session = active.filter(updated_at__gte=updated_at).first()

        return None if session is None else DjangoSessionRecord(session)

    def record_activity(
        self,
        session_id: object,
        *,
        last_active_at: datetime,
        since: datetime,
    ) -> DjangoSessionRecord | None:
        """Record a use of the session; this makes the storage a ``SessionActivityStorage``.

        Best-effort: a database error is logged and answers ``None``, so a
        failed write does not fail the request using the session.
        """
        try:
            with transaction.atomic(using=self.alias):
                # Once per interval: when concurrent requests use the session,
                # the first to commit records the use.
                recorded = (
                    self._one_token(session_id)
                    .filter(
                        revoked_at__isnull=True,
                        expire_date__gte=last_active_at,
                        last_activity__lte=since,
                    )
                    .update(last_activity=last_active_at)
                )
                session = self._one_token(session_id).first() if recorded else None
        except DatabaseError:
            logger.warning("Could not record a session's activity", exc_info=True)
            return None

        return None if session is None else DjangoSessionRecord(session)

    def revoke(self, session_id: object, *, revoked_at: datetime) -> bool:
        # end_sessions leaves an already revoked session's time as it is;
        # an expired session stays expired.
        active = self._one(session_id).filter(expire_date__gte=revoked_at)

        return end_sessions(active, at=revoked_at) > 0

    def revoke_all_for_user(
        self,
        user_id: object,
        *,
        revoked_at: datetime,
        except_session_id: object | None = None,
    ) -> int:
        """Revoke the user's active sessions: bearer tokens and browser sessions."""
        sessions = self._user_sessions(user_id).filter(expire_date__gte=revoked_at)
        if except_session_id is not None:
            kept = _public_id(except_session_id)
            # An id that can't match any row excludes nothing.
            if kept is not None:
                sessions = sessions.exclude(public_id=kept)

        return end_sessions(sessions, at=revoked_at)

    def clear_expired(self) -> int:
        """Delete the expired sessions of bearer tokens, revoked ones among them.

        ``clearsessions`` already does this, for browser sessions too, when
        ``SESSION_ENGINE`` is ``cross_auth.django.sessions``. With another
        engine, call it from scheduled maintenance, not requests.
        """
        deleted, _ = self._tokens().filter(expire_date__lt=timezone.now()).delete()
        return deleted


class DjangoMFAStorage:
    """Implements ``cross_auth.MFAStorage`` on ``MFAFactor`` and ``RecoveryCode``.

    It only stores rows: every 2FA rule is core's. The checks that must not
    let two requests both pass (a TOTP step, a recovery code, the failure
    count) are single conditional ``UPDATE`` statements. Every write first
    locks the user row, as ``DjangoStorage.disconnect_social_account`` does,
    and only then the factor or code rows, so writes for one user inside an
    application transaction wait for each other instead of deadlocking.
    """

    def __init__(self) -> None:
        self.alias = router.db_for_write(MFAFactor)
        if router.db_for_write(RecoveryCode) != self.alias:
            raise ImproperlyConfigured(
                "Cross Auth's MFAFactor and RecoveryCode must share a write database"
            )
        self._user_model = get_user_model()

    def _factors(self, user_id: object) -> QuerySet[MFAFactor]:
        user_id = _coerce_pk(self._user_model, user_id)
        factors = MFAFactor.objects.using(self.alias)
        return (
            factors.none() if user_id is _NO_MATCH else factors.filter(user_id=user_id)
        )

    def _codes(self, user_id: object) -> QuerySet[RecoveryCode]:
        user_id = _coerce_pk(self._user_model, user_id)
        codes = RecoveryCode.objects.using(self.alias)
        return codes.none() if user_id is _NO_MATCH else codes.filter(user_id=user_id)

    def _lock_user(self, user_id: object) -> bool:
        """Hold the user row until the surrounding transaction ends.

        Returns whether there is one: without it, nothing is locked. A no-op
        update: PostgreSQL keeps the row lock until commit, and SQLite takes
        its write lock before anything is read. Through the base manager, so
        a default manager that hides some users still locks theirs.
        """
        user_pk = _coerce_pk(self._user_model, user_id)
        if user_pk is _NO_MATCH:
            return False
        pk_name = self._user_model._meta.pk.name
        locked = (
            self._user_model._base_manager.using(self.alias)
            .filter(pk=user_pk)
            .update(**{pk_name: F(pk_name)})
        )
        return locked > 0

    def list_factors(self, user_id: Any) -> list[MFAFactor]:
        return list(self._factors(user_id).order_by("created_at", "id"))

    def create_factor(
        self,
        *,
        user_id: Any,
        type: str,
        name: str | None,
        data: Mapping[str, Any],
        created_at: datetime,
        last_used_step: int | None = None,
        recovery_code_hashes: Sequence[str] = (),
    ) -> tuple[MFAFactor, bool]:
        with transaction.atomic(using=self.alias):
            if not self._lock_user(user_id):
                raise ObjectDoesNotExist(f"No user {user_id!r} to add a factor to")
            # A new factor starts with the user's current lockout state.
            existing = self._factors(user_id).first()
            factor = MFAFactor(
                user_id=user_id,
                type=type,
                name=name,
                data=dict(data),
                created_at=created_at,
                last_used_step=last_used_step,
                failed_attempts=existing.failed_attempts if existing else 0,
                locked_until=existing.locked_until if existing else None,
            )
            factor.save(using=self.alias, force_insert=True)
            if existing is None:
                self._store_codes(user_id, recovery_code_hashes, created_at)
        return factor, existing is None

    def delete_factor(self, *, user_id: Any, factor_id: Any) -> int | None:
        factor_id = _coerce_pk(MFAFactor, factor_id)
        if factor_id is _NO_MATCH:
            return None
        with transaction.atomic(using=self.alias):
            if not self._lock_user(user_id):
                return None
            deleted, _ = self._factors(user_id).filter(pk=factor_id).delete()
            if not deleted:
                return None
            left = self._factors(user_id).count()
            if not left:
                self._codes(user_id).delete()
        return left

    def on_commit(self, callback: CommitCallback) -> None:
        # Inside ATOMIC_REQUESTS or the app's atomic(), after hooks wait for
        # the outermost commit, so a rollback sends no signal.
        transaction.on_commit(callback, using=self.alias, robust=False)

    def claim_totp_step(self, factor_id: Any, *, step: int, used_at: datetime) -> bool:
        factor_id = _coerce_pk(MFAFactor, factor_id)
        if factor_id is _NO_MATCH:
            return False
        factors = MFAFactor.objects.using(self.alias)
        user_id = factors.filter(pk=factor_id).values_list("user_id", flat=True).first()
        if user_id is None:
            return False
        with transaction.atomic(using=self.alias):
            # The user row before the factor's, as every write here. Inside an
            # application transaction a passing code goes on to reset the
            # failures under the user lock; holding its factor row first would
            # deadlock with a wrong code that holds the user lock.
            if not self._lock_user(user_id):
                return False
            return (
                factors.filter(
                    Q(last_used_step__isnull=True) | Q(last_used_step__lt=step),
                    pk=factor_id,
                ).update(last_used_step=step, last_used_at=used_at)
                > 0
            )

    # The lockout state lives on every factor row, and a new factor copies it:
    # changing it under the user lock means a factor created at the same time
    # gets the state from before or after, on every row alike. Without a user
    # row there are no factors, and nothing to do.

    def record_failure(self, user_id: Any) -> int:
        factors = self._factors(user_id)
        with transaction.atomic(using=self.alias):
            self._lock_user(user_id)
            factors.update(failed_attempts=F("failed_attempts") + 1)
            count = factors.values_list("failed_attempts", flat=True).first()
        return count or 0

    def lock(self, user_id: Any, *, until: datetime) -> None:
        with transaction.atomic(using=self.alias):
            self._lock_user(user_id)
            self._factors(user_id).update(failed_attempts=0, locked_until=until)

    def reset_failures(self, user_id: Any) -> None:
        with transaction.atomic(using=self.alias):
            self._lock_user(user_id)
            self._factors(user_id).update(failed_attempts=0, locked_until=None)

    def count_recovery_codes(self, user_id: Any) -> int:
        return self._codes(user_id).filter(used_at__isnull=True).count()

    def replace_recovery_codes(
        self, user_id: Any, code_hashes: Sequence[str], *, created_at: datetime
    ) -> bool:
        with transaction.atomic(using=self.alias):
            if not self._lock_user(user_id) or not self._factors(user_id).exists():
                return False
            self._store_codes(user_id, code_hashes, created_at)
        return True

    def _store_codes(
        self, user_id: Any, code_hashes: Sequence[str], created_at: datetime
    ) -> None:
        self._codes(user_id).delete()
        RecoveryCode.objects.using(self.alias).bulk_create(
            RecoveryCode(user_id=user_id, code_hash=code_hash, created_at=created_at)
            for code_hash in code_hashes
        )

    def use_recovery_code(
        self, user_id: Any, code_hash: str, *, used_at: datetime
    ) -> bool:
        with transaction.atomic(using=self.alias):
            # The user row before the code's, as in claim_totp_step: replacing
            # the codes holds the user lock while it deletes this row.
            if not self._lock_user(user_id):
                return False
            # One code at a time: two requests with the same code both match
            # the row, but only the first UPDATE still finds it unused.
            code = (
                self._codes(user_id)
                .filter(code_hash=code_hash, used_at__isnull=True)
                .values_list("pk", flat=True)
                .first()
            )
            if code is None:
                return False
            return (
                RecoveryCode.objects.using(self.alias)
                .filter(pk=code, used_at__isnull=True)
                .update(used_at=used_at)
                > 0
            )
