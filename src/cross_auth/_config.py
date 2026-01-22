from __future__ import annotations

from typing import Literal, TypedDict


class AccountLinkingConfig(TypedDict, total=False):
    """Account linking configuration."""

    # Enable automatic account linking by email?
    enabled: bool

    # Allow manual linking of accounts with different emails?
    allow_different_emails: bool


class SessionConfig(TypedDict, total=False):
    """Session-based authentication configuration."""

    # Cookie name for the session ID. Default: "session_id"
    cookie_name: str

    # Session lifetime in seconds. Default: 7 days (604800)
    expires_in: int

    # Refresh session when this many seconds remain before expiry.
    # Set to 0 to disable sliding sessions. Default: 1 day (86400)
    refresh_threshold: int

    # Cookie secure flag (HTTPS only). Default: True
    cookie_secure: bool

    # Cookie httponly flag (not accessible via JavaScript). Default: True
    cookie_httponly: bool

    # Cookie SameSite attribute. Default: "lax"
    cookie_samesite: Literal["lax", "strict", "none"]

    # Cookie path. Default: "/"
    cookie_path: str

    # Cookie domain. Default: None (current domain)
    cookie_domain: str | None


class Config(TypedDict, total=False):
    """Cross-auth configuration."""

    account_linking: AccountLinkingConfig

    # If True, reject OAuth signup when the provider reports the email as
    # unverified. This ensures new users have verified their email with the
    # OAuth provider before creating an account. Returning users with existing
    # linked accounts are not affected - they can still login.
    require_verified_email: bool

    # List of allowed client_ids. If not set or empty, client_id validation
    # is skipped (any client_id is accepted). When set, only these client_ids
    # are allowed to initiate OAuth flows.
    allowed_client_ids: list[str]
