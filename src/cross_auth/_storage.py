from collections.abc import Iterable, Sequence
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import AwareDatetime
from typing_extensions import Protocol

SessionStatus = Literal["active", "expired", "revoked"]
SessionListOrder = Literal[
    "updated_at_desc",
    "updated_at_asc",
    "created_at_desc",
    "created_at_asc",
    "expires_at_desc",
    "expires_at_asc",
]


class SocialAccount(Protocol):
    # Data members on this and the other record protocols are read-only
    # properties: core only reads them, and a plain protocol attribute would
    # demand an exact invariant match where a property lets concrete models
    # narrow the type (e.g. `provider_email_verified: bool`).
    @property
    def id(self) -> Any: ...

    @property
    def user_id(self) -> Any: ...

    @property
    def provider_user_id(self) -> str: ...

    @property
    def provider(self) -> str: ...

    @property
    def provider_email(self) -> str | None: ...

    @property
    def provider_email_verified(self) -> bool | None: ...

    # TODO: Add endpoint to toggle is_login_method for existing social accounts
    @property
    def is_login_method(self) -> bool: ...

    # Provider credentials. Core already writes these through
    # update_social_account/create_social_account kwargs; declaring them
    # readable lets token-less sign-ins preserve stored values.
    @property
    def access_token(self) -> str | None: ...

    @property
    def refresh_token(self) -> str | None: ...

    @property
    def access_token_expires_at(self) -> AwareDatetime | None: ...

    @property
    def refresh_token_expires_at(self) -> AwareDatetime | None: ...

    @property
    def scope(self) -> str | None: ...


class User(Protocol):
    @property
    def id(self) -> Any: ...

    # Nullable: apps may hold users without an email (created before email
    # capture, or via providers that withhold it). Core never reads this —
    # email lookups go through ``find_user_by_email``.
    @property
    def email(self) -> str | None: ...

    @property
    def email_verified(self) -> bool: ...

    @property
    def hashed_password(self) -> str | None: ...

    @property
    def has_usable_password(self) -> bool: ...

    @property
    def social_accounts(self) -> Iterable[SocialAccount]: ...


class SecondaryStorage(Protocol):
    def set(self, key: str, value: str, ttl: int | None = None) -> None:
        """Store a value.

        ``ttl`` is in seconds and must be enforced when provided; for some keys
        it is the only thing that expires the stored value.
        """
        ...

    def get(self, key: str) -> str | None: ...

    def delete(self, key: str) -> None: ...

    def pop(self, key: str) -> str | None:
        """Atomically get and delete a key. Returns None if key doesn't exist."""
        ...


class SessionRecord(Protocol):
    @property
    def id(self) -> Any: ...

    @property
    def user_id(self) -> Any: ...

    @property
    def created_at(self) -> AwareDatetime: ...

    @property
    def updated_at(self) -> AwareDatetime: ...

    @property
    def expires_at(self) -> AwareDatetime: ...

    @property
    def last_active_at(self) -> AwareDatetime | None: ...

    @property
    def revoked_at(self) -> AwareDatetime | None: ...

    @property
    def client_id(self) -> str | None: ...

    @property
    def client_name(self) -> str | None: ...

    @property
    def user_agent(self) -> str | None: ...

    @property
    def ip(self) -> str | None: ...

    @property
    def status(self) -> SessionStatus: ...


class SessionListResult(Protocol):
    # Read-only properties so implementations can return concrete model types
    # (e.g. list[MySessionRecord]) covariantly; a plain attribute would demand
    # an invariant match that no concrete implementation can satisfy.
    @property
    def records(self) -> Sequence[SessionRecord]: ...

    @property
    def next_cursor(self) -> str | None: ...


def session_status(
    record: SessionRecord,
    *,
    now: datetime | None = None,
) -> SessionStatus:
    """Derive a session's status from its revocation and expiry timestamps.

    This is the single source of truth for the active/expired/revoked state
    machine: storage implementations and ``SessionRecord.status`` properties
    should delegate here rather than re-deriving it. A session is ``active``
    up to and including the exact expiry instant. Naive datetimes are assumed
    to be UTC; ``now`` defaults to the current UTC time.
    """
    if record.revoked_at is not None:
        return "revoked"
    if now is None:
        now = datetime.now(tz=timezone.utc)
    elif now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    expires_at = record.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return "expired" if now > expires_at else "active"


class SessionStorage(Protocol):
    def create(
        self,
        *,
        token_hash: str,
        user_id: Any,
        created_at: AwareDatetime,
        updated_at: AwareDatetime,
        expires_at: AwareDatetime,
        client_id: str | None = None,
        client_name: str | None = None,
        user_agent: str | None = None,
        ip: str | None = None,
        last_active_at: AwareDatetime | None = None,
    ) -> SessionRecord: ...

    def get(
        self,
        *,
        token_hash: str,
        now: AwareDatetime,
    ) -> SessionRecord | None: ...

    def get_any(self, session_id: Any) -> SessionRecord | None: ...

    def list_for_user(
        self,
        user_id: Any,
        *,
        now: AwareDatetime,
        status: SessionStatus | None = None,
        order_by: SessionListOrder = "updated_at_desc",
        limit: int = 50,
        cursor: str | None = None,
    ) -> SessionListResult: ...

    def refresh(
        self,
        session_id: Any,
        *,
        updated_at: AwareDatetime,
        expires_at: AwareDatetime,
        last_active_at: AwareDatetime | None = None,
    ) -> SessionRecord | None:
        """Roll a session forward. When ``last_active_at`` is omitted (None),
        the stored value is preserved rather than cleared."""
        ...

    def revoke(
        self,
        session_id: Any,
        *,
        revoked_at: AwareDatetime,
    ) -> None: ...

    def revoke_all_for_user(
        self,
        user_id: Any,
        *,
        revoked_at: AwareDatetime,
        except_session_id: Any | None = None,
    ) -> int: ...


class AccountsStorage(Protocol):
    def find_user_by_email(self, email: str) -> User | None: ...

    def find_user_by_id(self, id: Any) -> User | None: ...

    def find_social_account(
        self,
        *,
        provider: str,
        provider_user_id: str,
    ) -> SocialAccount | None: ...

    def find_social_account_by_id(
        self,
        social_account_id: Any,
    ) -> SocialAccount | None: ...

    def list_social_accounts(self, *, user_id: Any) -> Iterable[SocialAccount]: ...

    def create_user(
        self,
        *,
        user_info: dict[str, Any],
        email: str,
        email_verified: bool,
    ) -> User: ...

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
    ) -> SocialAccount: ...

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
    ) -> SocialAccount: ...

    def delete_social_account(self, social_account_id: Any) -> None: ...
