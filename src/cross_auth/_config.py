from __future__ import annotations

from typing import TypedDict

from ._session import SessionConfig


class AccountLinkingConfig(TypedDict, total=False):
    """Account linking configuration."""

    # Enable automatic account linking by email?
    enabled: bool

    # Allow manual linking of accounts with different emails?
    allow_different_emails: bool

    # Defaults to False. The database schema must enforce the same policy.
    allow_shared_connections: bool


class Config(TypedDict, total=False):
    """Cross-auth configuration."""

    account_linking: AccountLinkingConfig

    # If True, reject OAuth signup when the provider reports the email as
    # unverified. This ensures new users have verified their email with the
    # OAuth provider before creating an account. Returning users with existing
    # linked accounts are not affected - they can still login.
    require_verified_email: bool

    # Session settings, including cookies.auth to enable browser
    # /{provider}/login routes. Cookie sign-in requires session_storage.
    session: SessionConfig
