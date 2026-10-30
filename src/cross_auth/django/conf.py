"""Settings for the Django integration, read from ``settings.CROSS_AUTH``."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import timedelta
from functools import cache
from typing import Any, Protocol

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.models import UserManager
from django.core.exceptions import ImproperlyConfigured
from django.core.signals import setting_changed
from django.utils.module_loading import import_string

from cross_auth._config import AccountLinkingConfig
from cross_auth.social_providers.oauth import OAuth2Provider


class UserFactory(Protocol):
    """Creates the native user for a first provider sign-in.

    Runs inside the transaction that also stores the user's first identity,
    so rows it writes roll back together with them. It must not call external
    services; send notifications from a ``user_created`` receiver instead.
    ``email`` is normalized; ``extra_fields`` is empty.
    """

    def __call__(
        self,
        *,
        email: str,
        user_info: Mapping[str, Any],
        extra_fields: Mapping[str, Any],
    ) -> AbstractBaseUser: ...


def create_user(
    *,
    email: str,
    user_info: Mapping[str, Any],
    extra_fields: Mapping[str, Any],
) -> AbstractBaseUser:
    """Default factory for models managed by Django's ``UserManager``.

    Uses the email as the username and leaves the user without a usable
    password. Other user models need ``CROSS_AUTH["CREATE_USER"]``.
    """
    manager = get_user_model()._default_manager
    if not isinstance(manager, UserManager):
        raise ImproperlyConfigured(
            "The default Cross Auth user factory needs a user model managed by "
            "django.contrib.auth.models.UserManager; set CROSS_AUTH['CREATE_USER']"
        )
    user = manager.create_user(email, email=email, **extra_fields)
    if not isinstance(user, AbstractBaseUser):
        raise TypeError("UserManager.create_user did not return a user")
    return user


@dataclass(frozen=True)
class CrossAuthSettings:
    providers: Mapping[str, OAuth2Provider]
    create_user: UserFactory
    # Whether users can sign in with their Django password. When True, a
    # usable password counts as another way to sign in, so the last provider
    # identity can be disconnected.
    password_login: bool
    account_linking: AccountLinkingConfig
    require_verified_email: bool
    # Public origin used for provider callback URLs instead of the request's.
    base_url: str | None
    # How stale cross_auth.django.sessions lets a session's last_activity get
    # before a request that does not save the session updates it.
    session_activity_interval: timedelta


_KNOWN_KEYS = frozenset(
    {
        "PROVIDERS",
        "CREATE_USER",
        "PASSWORD_LOGIN",
        "ACCOUNT_LINKING",
        "REQUIRE_VERIFIED_EMAIL",
        "BASE_URL",
        "SESSION_ACTIVITY_INTERVAL",
    }
)
_ACCOUNT_LINKING_KEYS = frozenset({"enabled", "allow_different_emails"})
# A year. Sessions compare their last_activity with now minus the interval,
# which must stay a date that Python and the database can hold.
_MAX_SESSION_ACTIVITY_INTERVAL = 365 * 24 * 60 * 60


def _bool(
    raw: Mapping[Any, object], key: str, default: bool, *, prefix: str = ""
) -> bool:
    value = raw.get(key, default)
    if not isinstance(value, bool):
        raise ImproperlyConfigured(f"CROSS_AUTH{prefix}['{key}'] must be a bool")
    return value


def _seconds(
    raw: Mapping[str, object], key: str, default: int, *, maximum: int
) -> timedelta:
    value = raw.get(key, default)
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value <= maximum
    ):
        raise ImproperlyConfigured(
            f"CROSS_AUTH['{key}'] must be a number of seconds, an int from 0 to "
            f"{maximum}"
        )
    return timedelta(seconds=value)


def _providers(value: object) -> dict[str, OAuth2Provider]:
    if not isinstance(value, (list, tuple)):
        raise ImproperlyConfigured("CROSS_AUTH['PROVIDERS'] must be a list")
    providers: dict[str, OAuth2Provider] = {}
    for provider in value:
        if not isinstance(provider, OAuth2Provider):
            raise ImproperlyConfigured(
                "CROSS_AUTH['PROVIDERS'] must contain provider instances such as "
                "GoogleProvider(...)"
            )
        if provider.id in providers:
            raise ImproperlyConfigured(
                f"CROSS_AUTH['PROVIDERS'] lists {provider.id!r} more than once"
            )
        providers[provider.id] = provider
    return providers


def _account_linking(value: object) -> AccountLinkingConfig:
    if not isinstance(value, Mapping):
        raise ImproperlyConfigured("CROSS_AUTH['ACCOUNT_LINKING'] must be a dict")
    unknown = set(value) - _ACCOUNT_LINKING_KEYS
    if unknown:
        # allow_shared_connections is not offered: the schema gives each
        # identity exactly one owner.
        raise ImproperlyConfigured(
            "Unsupported CROSS_AUTH['ACCOUNT_LINKING'] key(s): "
            + ", ".join(sorted(unknown))
        )
    return AccountLinkingConfig(
        enabled=_bool(value, "enabled", False, prefix="['ACCOUNT_LINKING']"),
        allow_different_emails=_bool(
            value, "allow_different_emails", False, prefix="['ACCOUNT_LINKING']"
        ),
    )


@cache
def get_settings() -> CrossAuthSettings:
    raw: Mapping[str, Any] = getattr(settings, "CROSS_AUTH", {})
    unknown = set(raw) - _KNOWN_KEYS
    if unknown:
        raise ImproperlyConfigured(
            f"Unknown CROSS_AUTH setting(s): {', '.join(sorted(unknown))}"
        )

    factory: UserFactory = create_user
    factory_path = raw.get("CREATE_USER")
    if factory_path is not None:
        if not isinstance(factory_path, str):
            raise ImproperlyConfigured(
                "CROSS_AUTH['CREATE_USER'] must be the dotted path of a function"
            )
        factory = import_string(factory_path)
        if not callable(factory):
            raise ImproperlyConfigured(
                f"CROSS_AUTH['CREATE_USER'] {factory_path!r} is not callable"
            )

    base_url = raw.get("BASE_URL")
    if base_url is not None and not (
        isinstance(base_url, str) and base_url.startswith(("https://", "http://"))
    ):
        raise ImproperlyConfigured(
            "CROSS_AUTH['BASE_URL'] must be an origin such as https://example.com"
        )

    return CrossAuthSettings(
        providers=_providers(raw.get("PROVIDERS", [])),
        create_user=factory,
        password_login=_bool(raw, "PASSWORD_LOGIN", True),
        account_linking=_account_linking(raw.get("ACCOUNT_LINKING", {})),
        require_verified_email=_bool(raw, "REQUIRE_VERIFIED_EMAIL", True),
        base_url=base_url,
        session_activity_interval=_seconds(
            raw,
            "SESSION_ACTIVITY_INTERVAL",
            60,
            maximum=_MAX_SESSION_ACTIVITY_INTERVAL,
        ),
    )


def _reset(*, setting: str, **kwargs: object) -> None:
    if setting in {"CROSS_AUTH", "AUTH_USER_MODEL"}:
        get_settings.cache_clear()


setting_changed.connect(_reset)
