from datetime import datetime
from typing import Any, Iterable

from typing_extensions import Protocol


class SocialAccount(Protocol):
    id: Any
    user_id: Any
    provider_user_id: str
    provider: str
    provider_email: str | None
    provider_email_verified: bool | None
    # TODO: Add endpoint to toggle is_login_method for existing social accounts
    is_login_method: bool


class User(Protocol):
    id: Any
    email: str
    email_verified: bool
    hashed_password: str | None

    @property
    def social_accounts(self) -> Iterable[SocialAccount]: ...


class SecondaryStorage(Protocol):
    def set(self, key: str, value: str): ...

    def get(self, key: str) -> str | None: ...

    def delete(self, key: str): ...

    def pop(self, key: str) -> str | None:
        """Atomically get and delete a key. Returns None if key doesn't exist."""
        ...


class AccountsStorage(Protocol):
    def find_user_by_email(self, email: str) -> User | None: ...

    def find_user_by_id(self, id: Any) -> User | None: ...

    def find_social_account(
        self,
        *,
        provider: str,
        provider_user_id: str,
    ) -> SocialAccount | None: ...

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
