"""Shared SQLModel test models for the storage adapter tests.

Defined once at module level so every table is registered on
``SQLModel.metadata`` before the conftest engine runs ``create_all``.
"""

import uuid
from datetime import datetime

from sqlalchemy import Column, DateTime, Index, UniqueConstraint, text
from sqlmodel import Field, Relationship, SQLModel
from sqlmodel.sql.expression import SelectOfScalar

from cross_auth.storage.sqlmodel import (
    SQLModelAccountsStorage,
    SQLModelSession,
    SQLModelUser,
    SQLModelSocialAccount,
    SQLModelSessionStorage,
)


class UserSession(SQLModelSession, table=True):
    id: int | None = Field(default=None, primary_key=True)
    user_id: str = Field(index=True)


class SessionStore(SQLModelSessionStorage[UserSession]):
    SessionModel = UserSession


class UuidUserSession(SQLModelSession, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    user_id: str = Field(index=True)


class UuidSessionStore(SQLModelSessionStorage[UuidUserSession]):
    SessionModel = UuidUserSession


class IntUserIdSession(SQLModelSession, table=True):
    """Session model whose ``user_id`` is an integer foreign-key-style column.
    Cross-Auth passes user ids as strings; the adapter coerces them to the
    column type."""

    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(index=True)


class IntUserIdSessionStore(SQLModelSessionStorage[IntUserIdSession]):
    SessionModel = IntUserIdSession


class RenamedColumnSession(SQLModelSession, table=True):
    """Session model whose id and datetime columns are mapped to differently
    named database columns. The adapter must resolve columns by the Python
    attribute name, not the database column name."""

    id: int | None = Field(
        default=None, primary_key=True, sa_column_kwargs={"name": "session_pk"}
    )
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


class RenamedColumnSessionStore(SQLModelSessionStorage[RenamedColumnSession]):
    SessionModel = RenamedColumnSession


class TzAwareUserSession(SQLModelSession, table=True):
    """Session model with timezone-aware (``timestamptz``) datetime columns, the
    alternative to the naive-column default the other models use."""

    id: int | None = Field(default=None, primary_key=True)
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


class TzAwareSessionStore(SQLModelSessionStorage[TzAwareUserSession]):
    SessionModel = TzAwareUserSession


class StoredSocialAccountBase(SQLModelSocialAccount):
    access_token: str | None = None
    refresh_token: str | None = None
    access_token_expires_at: datetime | None = None
    refresh_token_expires_at: datetime | None = None
    scope: str | None = None


class SocialAccount(StoredSocialAccountBase, table=True):
    __table_args__ = (UniqueConstraint("provider", "provider_user_id"),)

    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id")
    provider_username: str | None = None

    user: "User" = Relationship(back_populates="social_accounts")


class User(SQLModelUser, table=True):
    id: int | None = Field(default=None, primary_key=True)
    email: str = Field(index=True)
    email_verified: bool = False
    deleted: bool = False
    updated_at: datetime = Field(
        default_factory=datetime.now, sa_column_kwargs={"onupdate": datetime.now}
    )

    social_accounts: list[SocialAccount] = Relationship(
        back_populates="user", sa_relationship_kwargs={"lazy": "selectin"}
    )


class AccountsStore(SQLModelAccountsStorage[User, SocialAccount]):
    UserModel = User
    SocialAccountModel = SocialAccount


class DefaultLazySocialAccount(StoredSocialAccountBase, table=True):
    """Relationship-backed account model with SQLAlchemy's default lazy load."""

    __tablename__ = "default_lazy_social_account"

    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="default_lazy_user.id")

    user: "DefaultLazyUser" = Relationship(back_populates="social_accounts")


class DefaultLazyUser(SQLModelUser, table=True):
    """Relationship-backed user without an application eager-load setting."""

    __tablename__ = "default_lazy_user"

    id: int | None = Field(default=None, primary_key=True)
    email_verified: bool = False

    social_accounts: list[DefaultLazySocialAccount] = Relationship(
        back_populates="user"
    )


class DefaultLazyAccountsStore(
    SQLModelAccountsStorage[DefaultLazyUser, DefaultLazySocialAccount]
):
    UserModel = DefaultLazyUser
    SocialAccountModel = DefaultLazySocialAccount


class RelationshipFreeUser(SQLModelUser, table=True):
    """User model that keeps account access entirely in storage queries."""

    __tablename__ = "relationship_free_user"

    id: int | None = Field(default=None, primary_key=True)
    email_verified: bool = False


class RelationshipFreeSocialAccount(StoredSocialAccountBase, table=True):
    __tablename__ = "relationship_free_social_account"
    __table_args__ = (UniqueConstraint("provider", "provider_user_id"),)

    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="relationship_free_user.id")


class RelationshipFreeAccountsStore(
    SQLModelAccountsStorage[RelationshipFreeUser, RelationshipFreeSocialAccount]
):
    UserModel = RelationshipFreeUser
    SocialAccountModel = RelationshipFreeSocialAccount


class SoftDeleteAccountsStore(AccountsStore):
    def filter_user_query(
        self, statement: SelectOfScalar[User]
    ) -> SelectOfScalar[User]:
        return statement.where(User.deleted == False)  # noqa: E712


class LeanSocialAccount(SQLModelSocialAccount, table=True):
    """Social account that reads credentials but does not persist them."""

    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id")

    @property
    def access_token(self) -> None:
        return None

    @property
    def refresh_token(self) -> None:
        return None

    @property
    def access_token_expires_at(self) -> None:
        return None

    @property
    def refresh_token_expires_at(self) -> None:
        return None

    @property
    def scope(self) -> None:
        return None


class LeanAccountsStore(AccountsStore):
    SocialAccountModel = LeanSocialAccount  # type: ignore[assignment]
    excluded_social_account_fields = frozenset(
        {
            "access_token",
            "refresh_token",
            "access_token_expires_at",
            "refresh_token_expires_at",
            "scope",
        }
    )


class PropertyScopeSocialAccount(SQLModelSocialAccount, table=True):
    """A social account whose ``scope`` write field is a read-only property
    instead of a mapped column. ``hasattr(model, "scope")`` is True here, but
    SQLModel's constructor only accepts pydantic fields — a property is
    silently dropped rather than set, which is exactly the failure mode the
    write-field validation exists to catch at construction."""

    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id")
    access_token: str | None = None
    refresh_token: str | None = None
    access_token_expires_at: datetime | None = None
    refresh_token_expires_at: datetime | None = None

    @property
    def scope(self) -> str | None:
        return None


class AliasedVerifiedUser(SQLModelUser, table=True):
    """Cloud-style user with required profile data and renamed verification."""

    id: int | None = Field(default=None, primary_key=True)
    email: str = Field(index=True)
    full_name: str
    is_verified: bool = False

    @property
    def email_verified(self) -> bool:
        return self.is_verified

    @email_verified.setter
    def email_verified(self, value: bool) -> None:
        self.is_verified = value


class AttachmentAccountBase(StoredSocialAccountBase):
    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id")
    external_reference: str | None = Field(default=None, unique=True)


class ExclusiveAttachmentAccount(AttachmentAccountBase, table=True):
    __table_args__ = (UniqueConstraint("provider", "provider_user_id"),)


class SharedAttachmentAccount(AttachmentAccountBase, table=True):
    __table_args__ = (
        UniqueConstraint("user_id", "provider", "provider_user_id"),
        Index(
            "uq_sharedattachmentaccount_login_identity",
            "provider",
            "provider_user_id",
            unique=True,
            sqlite_where=text("is_login_method = true"),
            postgresql_where=text("is_login_method = true"),
        ),
    )


class SignupApplicationRow(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id")
    label: str
    user: User = Relationship()
