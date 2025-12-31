from __future__ import annotations

from typing import TypedDict


class AccountLinkingConfig(TypedDict, total=False):
    """Account linking configuration."""

    # Automatically link accounts by verified email?
    link_by_email: bool

    # Allow linking accounts with different emails?
    allow_different_emails: bool


class Config(TypedDict, total=False):
    """Cross-auth configuration."""

    account_linking: AccountLinkingConfig
