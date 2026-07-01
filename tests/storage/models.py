"""Shared SQLModel test models for the storage adapter tests.

Defined once at module level so every table is registered on
``SQLModel.metadata`` before the conftest engine runs ``create_all``.
"""

import uuid
from datetime import datetime

from sqlalchemy import Column, DateTime
from sqlmodel import Field, Relationship, Session, SQLModel
from sqlmodel.sql.expression import SelectOfScalar

from cross_auth import SessionStatus, session_status
from cross_auth.storage.sqlmodel import (
    SQLModelAccountsStorage,
    SQLModelSessionStorage,
)


class UserSession(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    token_hash: str = Field(index=True)
    user_id: str = Field(index=True)
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


class SessionStore(SQLModelSessionStorage[UserSession]):
    SessionModel = UserSession


class UuidUserSession(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    token_hash: str = Field(index=True)
    user_id: str = Field(index=True)
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


class UuidSessionStore(SQLModelSessionStorage[UuidUserSession]):
    SessionModel = UuidUserSession


class IntUserIdSession(SQLModel, table=True):
    """Session model whose ``user_id`` is an integer foreign-key-style column.
    Cross-Auth passes user ids as strings; the adapter coerces them to the
    column type."""

    id: int | None = Field(default=None, primary_key=True)
    token_hash: str = Field(index=True)
    user_id: int = Field(index=True)
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


class IntUserIdSessionStore(SQLModelSessionStorage[IntUserIdSession]):
    SessionModel = IntUserIdSession


class RenamedColumnSession(SQLModel, table=True):
    """Session model whose id and datetime columns are mapped to differently
    named database columns. The adapter must resolve columns by the Python
    attribute name, not the database column name."""

    id: int | None = Field(
        default=None, primary_key=True, sa_column_kwargs={"name": "session_pk"}
    )
    token_hash: str = Field(index=True)
    user_id: str = Field(index=True)
    created_at: datetime = Field(sa_column_kwargs={"name": "created_ts"})
    updated_at: datetime = Field(sa_column_kwargs={"name": "updated_ts"})
    expires_at: datetime = Field(sa_column_kwargs={"name": "expires_ts"})
    last_active_at: datetime | None = Field(
        default=None, sa_column_kwargs={"name": "last_active_ts"}
    )
    revoked_at: datetime | None = Field(
        default=None, sa_column_kwargs={"name": "revoked_ts"}
    )
    client_id: str | None = None
    client_name: str | None = None
    user_agent: str | None = None
    ip: str | None = None

    @property
    def status(self) -> SessionStatus:
        return session_status(self)


class RenamedColumnSessionStore(SQLModelSessionStorage[RenamedColumnSession]):
    SessionModel = RenamedColumnSession


class TzAwareUserSession(SQLModel, table=True):
    """Session model with timezone-aware (``timestamptz``) datetime columns, the
    alternative to the naive-column default the other models use."""

    id: int | None = Field(default=None, primary_key=True)
    token_hash: str = Field(index=True)
    user_id: str = Field(index=True)
    created_at: datetime = Field(sa_column=Column(DateTime(timezone=True)))
    updated_at: datetime = Field(sa_column=Column(DateTime(timezone=True)))
    expires_at: datetime = Field(sa_column=Column(DateTime(timezone=True)))
    last_active_at: datetime | None = Field(
        default=None, sa_column=Column(DateTime(timezone=True))
    )
    revoked_at: datetime | None = Field(
        default=None, sa_column=Column(DateTime(timezone=True))
    )
    client_id: str | None = None
    client_name: str | None = None
    user_agent: str | None = None
    ip: str | None = None

    @property
    def status(self) -> SessionStatus:
        return session_status(self)


class TzAwareSessionStore(SQLModelSessionStorage[TzAwareUserSession]):
    SessionModel = TzAwareUserSession


class SocialAccount(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id")
    provider: str
    provider_user_id: str
    access_token: str | None = None
    refresh_token: str | None = None
    access_token_expires_at: datetime | None = None
    refresh_token_expires_at: datetime | None = None
    scope: str | None = None
    provider_email: str | None = None
    provider_email_verified: bool | None = None
    is_login_method: bool = True

    user: "User" = Relationship(back_populates="social_accounts")


class User(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    email: str = Field(index=True)
    email_verified: bool = False
    hashed_password: str | None = None
    deleted: bool = False

    social_accounts: list[SocialAccount] = Relationship(back_populates="user")

    @property
    def has_usable_password(self) -> bool:
        return self.hashed_password is not None


class AccountsStore(SQLModelAccountsStorage[User, SocialAccount]):
    UserModel = User
    SocialAccountModel = SocialAccount

    def on_signup(
        self,
        *,
        session: Session,
        user: User,
        user_info: dict[str, object],
        email_verified: bool,
    ) -> None:
        hashed_password = user_info.get("hashed_password")
        assert hashed_password is None or isinstance(hashed_password, str)
        user.hashed_password = hashed_password


class SoftDeleteAccountsStore(AccountsStore):
    def filter_user_query(
        self, statement: SelectOfScalar[User]
    ) -> SelectOfScalar[User]:
        return statement.where(User.deleted == False)  # noqa: E712


class LeanSocialAccount(SQLModel, table=True):
    """Social account without the token/scope columns — for an app that never
    persists provider tokens. Only valid together with payload builders that
    drop those fields (see LeanAccountsStore)."""

    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id")
    provider: str
    provider_user_id: str
    provider_email: str | None = None
    provider_email_verified: bool | None = None
    is_login_method: bool = True


_TOKEN_FIELDS = (
    "access_token",
    "refresh_token",
    "access_token_expires_at",
    "refresh_token_expires_at",
    "scope",
)


class LeanAccountsStore(AccountsStore):
    SocialAccountModel = LeanSocialAccount  # type: ignore[assignment]

    def build_social_account_create_values(
        self, *, user_info: dict[str, object], **fields: object
    ) -> dict[str, object]:
        return {k: v for k, v in fields.items() if k not in _TOKEN_FIELDS}

    def build_social_account_update_values(
        self,
        *,
        user_info: dict[str, object],
        # Annotated with the class's declared generic (the runtime rows are
        # LeanSocialAccount, see the SocialAccountModel reassignment above).
        record: SocialAccount,
        **fields: object,
    ) -> dict[str, object]:
        return {k: v for k, v in fields.items() if k not in _TOKEN_FIELDS}


class PropertyScopeSocialAccount(SQLModel, table=True):
    """A social account whose ``scope`` write field is a read-only property
    instead of a mapped column. ``hasattr(model, "scope")`` is True here, but
    SQLModel's constructor only accepts pydantic fields — a property is
    silently dropped rather than set, which is exactly the failure mode the
    write-field validation exists to catch at construction."""

    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id")
    provider: str
    provider_user_id: str
    access_token: str | None = None
    refresh_token: str | None = None
    access_token_expires_at: datetime | None = None
    refresh_token_expires_at: datetime | None = None
    provider_email: str | None = None
    provider_email_verified: bool | None = None
    is_login_method: bool = True

    @property
    def scope(self) -> str | None:
        return None


class PropUser(SQLModel, table=True):
    """A protocol-compliant user whose ``social_accounts`` is a plain property
    rather than an ORM relationship."""

    id: int | None = Field(default=None, primary_key=True)
    email: str = Field(index=True)
    email_verified: bool = False
    hashed_password: str | None = None

    @property
    def has_usable_password(self) -> bool:
        return self.hashed_password is not None

    @property
    def social_accounts(self) -> list[SocialAccount]:
        return []


class PropAccountsStore(SQLModelAccountsStorage[PropUser, SocialAccount]):
    UserModel = PropUser
    SocialAccountModel = SocialAccount
