from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from django.conf import settings
from django.contrib.sessions.base_session import AbstractBaseSession
from django.db import models
from django.utils import timezone

if TYPE_CHECKING:
    from .sessions import SessionStore


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


class Session(AbstractBaseSession):
    """A Django session that knows its user, login method and device.

    The session store of ``SESSION_ENGINE = "cross_auth.django.sessions"``
    keeps sessions here instead of in ``django_session``, and fills the
    columns from the session's data and its request each time it saves.
    Read them, but change sessions through Django or the helpers in
    ``cross_auth.django.sessions``.

    ``session_key`` is the session cookie's value: never show it. Pages and
    forms name a session by ``public_id``.
    """

    if TYPE_CHECKING:
        user_id: Any

    public_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    # Null while the session is anonymous.
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="cross_auth_sessions",
    )
    # The provider of a Cross Auth sign-in; null for anonymous sessions and
    # other logins, such as Django's password login.
    login_method = models.CharField(max_length=64, null=True, blank=True)
    user_agent = models.CharField(max_length=512, null=True, blank=True)
    ip = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    last_activity = models.DateTimeField(default=timezone.now)

    def __str__(self) -> str:
        return str(self.public_id)

    @classmethod
    def get_session_store_class(cls) -> type[SessionStore]:
        from .sessions import SessionStore

        return SessionStore
