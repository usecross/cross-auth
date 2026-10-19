from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any

from django.conf import settings
from django.db import models


class SocialAccount(models.Model):
    """A provider identity connected to a native Django user.

    One row owns each provider identity: the database rejects a second user
    connecting the same ``(provider, provider_user_id)``. The provider's email
    and its verification flag stay on this row; they never change the user's
    own email. Provider access and refresh tokens are not stored.
    """

    # Django adds these fields; declare them for type checkers. ``user_id``
    # takes the type of the configured user model's primary key.
    if TYPE_CHECKING:
        id: int
        user_id: Any

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="cross_auth_social_accounts",
    )
    provider = models.CharField(max_length=64)
    provider_user_id = models.CharField(max_length=255)
    provider_email = models.CharField(max_length=320, null=True, blank=True)
    provider_email_verified = models.BooleanField(null=True)
    is_login_method = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["provider", "provider_user_id"],
                name="cross_auth_unique_identity",
            )
        ]

    def __str__(self) -> str:
        return f"{self.provider}:{self.provider_user_id}"

    # The pilot keeps provider credentials out of the database. Cross Auth's
    # SocialAccount protocol reads them, so they are always empty here.
    @property
    def access_token(self) -> str | None:
        return None

    @property
    def refresh_token(self) -> str | None:
        return None

    @property
    def access_token_expires_at(self) -> datetime | None:
        return None

    @property
    def refresh_token_expires_at(self) -> datetime | None:
        return None

    @property
    def scope(self) -> str | None:
        return None


class ExpiringValue(models.Model):
    """Short-lived OAuth state and provider key caches.

    Values with an ``expires_at`` in the past are treated as missing and are
    purged as new values are written.
    """

    key = models.CharField(max_length=255, primary_key=True)
    value = models.TextField()
    expires_at = models.DateTimeField(null=True, db_index=True)

    def __str__(self) -> str:
        return self.key
