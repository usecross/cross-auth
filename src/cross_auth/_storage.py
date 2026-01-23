from datetime import datetime
from typing import Any, Iterable

from typing_extensions import Protocol


class Session(Protocol):
    """Session protocol for session-based authentication."""

    id: str
    user_id: Any
    expires_at: datetime
    created_at: datetime
    ip_address: str | None
    user_agent: str | None


class SessionStorage(Protocol):
    """Storage protocol for session management."""

    def create_session(
        self,
        user_id: Any,
        expires_at: datetime,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> Session:
        """Create a new session for a user."""
        ...

    def get_session(self, session_id: str) -> Session | None:
        """Get a session by its ID. Returns None if not found or expired."""
        ...

    def delete_session(self, session_id: str) -> None:
        """Delete a session by its ID."""
        ...

    def delete_user_sessions(self, user_id: Any) -> None:
        """Delete all sessions for a user."""
        ...

    def list_user_sessions(self, user_id: Any) -> list[Session]:
        """List all active sessions for a user."""
        ...

    def update_session_expiry(self, session_id: str, expires_at: datetime) -> None:
        """Update the expiry time of a session (for sliding sessions)."""
        ...


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

    def create_user_with_password(
        self,
        *,
        email: str,
        hashed_password: str,
        email_verified: bool = False,
        user_info: dict[str, Any] | None = None,
    ) -> User:
        """Create a new user with email and password.

        This is used for email/password signup flows.

        Args:
            email: The user's email address
            hashed_password: The bcrypt-hashed password
            email_verified: Whether the email has been verified (default: False)
            user_info: Optional additional user info

        Returns:
            The created user

        Raises:
            ValueError or similar if user with email already exists
        """
        ...
