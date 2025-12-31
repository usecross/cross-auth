from __future__ import annotations

from dataclasses import dataclass


@dataclass
class AccountLinkingConfig:
    """Global account linking configuration."""

    # Automatically link accounts by verified email?
    link_by_email: bool = False

    # Providers to trust (bypass verification checks for linking)
    # None = trust all, [] = trust none
    trusted_providers: list[str] | None = None

    # Allow linking accounts with different emails?
    allow_different_emails: bool = False

    def is_trusted_provider(self, provider_id: str) -> bool:
        if self.trusted_providers is None:
            return True
        return provider_id in self.trusted_providers
