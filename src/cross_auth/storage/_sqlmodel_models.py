"""Shared fields and application-defined attributes for SQLModel adapters."""

from collections.abc import Iterable
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlmodel import Field, SQLModel

from cross_auth._storage import SessionStatus, SocialAccount, session_status


class SQLModelSession(SQLModel):
    """Session fields; subclasses declare their primary key and user ID column."""

    # IDs belong to the application's schema. Declaring them only for typing
    # avoids imposing a SQL type, primary-key strategy, or foreign-key target.
    # Storage construction checks that the concrete table exposes them.
    if TYPE_CHECKING:
        id: Any
        user_id: Any

    token_hash: str = Field(index=True)
    created_at: datetime
    updated_at: datetime
    expires_at: datetime
    last_active_at: datetime | None = None
    revoked_at: datetime | None = None
    client_id: str | None = None
    client_name: str | None = None
    user_agent: str | None = None
    ip: str | None = None

    @property
    def status(self) -> SessionStatus:
        return session_status(self)


class SQLModelUser(SQLModel):
    """User fields; subclasses supply ID, verification, and social accounts.

    ``email_verified`` may be a column or a writable property. Declare
    ``social_accounts`` as a relationship or a property returning accounts.
    """

    if TYPE_CHECKING:
        id: Any

        @property
        def email_verified(self) -> bool: ...

        @email_verified.setter
        def email_verified(self, value: bool) -> None: ...

        @property
        def social_accounts(self) -> Iterable[SocialAccount]: ...

    email: str | None = Field(index=True)
    hashed_password: str | None = None

    @property
    def has_usable_password(self) -> bool:
        return self.hashed_password is not None


class SQLModelSocialAccount(SQLModel):
    """Identity fields; subclasses supply IDs and provider credential fields.

    Credential fields can be columns or read-only properties. When credentials
    are not persisted, configure ``excluded_social_account_fields`` on the store.
    Identity uniqueness and foreign-key constraints belong to the application.
    """

    if TYPE_CHECKING:
        id: Any
        user_id: Any

        @property
        def access_token(self) -> str | None: ...

        @property
        def refresh_token(self) -> str | None: ...

        @property
        def access_token_expires_at(self) -> datetime | None: ...

        @property
        def refresh_token_expires_at(self) -> datetime | None: ...

        @property
        def scope(self) -> str | None: ...

    provider: str
    provider_user_id: str
    provider_email: str | None = None
    provider_email_verified: bool | None = None
    is_login_method: bool = True
