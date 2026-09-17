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

    # Simple static web-client registry. For database-backed or native clients,
    # supply get_client instead. Without either registry, broker flows reject clients.
    client_redirect_uris: dict[str, list[str]]

    # Session cookie settings (cookie name, max_age, secure, etc.) plus the
    # cookie_auth flag that enables the browser /{provider}/login flow. See
    # SessionConfig. cookie_auth requires session_storage to be provided.
    session: SessionConfig
