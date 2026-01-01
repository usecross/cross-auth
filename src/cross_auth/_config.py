from __future__ import annotations

from typing import TypedDict


class AccountLinkingConfig(TypedDict, total=False):
    """Account linking configuration."""

    # Enable automatic account linking by email?
    enabled: bool

    # Allow manual linking of accounts with different emails?
    allow_different_emails: bool


class Config(TypedDict, total=False):
    """Cross-auth configuration."""

    account_linking: AccountLinkingConfig

    # If True, reject OAuth login/signup when the provider reports the email
    # as unverified. This ensures users have verified their email with the
    # OAuth provider before accessing the application.
    require_verified_email: bool
