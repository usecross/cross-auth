"""Settings for the Django integration, read from ``settings.CROSS_AUTH``."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from functools import cache
from typing import Any, Protocol

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.models import UserManager
from django.core.exceptions import ImproperlyConfigured
from django.core.signals import setting_changed
from django.utils.module_loading import import_string


class UserFactory(Protocol):
    """Creates the native user for a first provider sign-in.

    Runs inside the transaction that also stores the user's first identity,
    so rows it writes roll back together with them. It must not call external
    services. ``email`` is normalized; ``extra_fields`` come from
    ``user.create`` before hooks.
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
    create_user: UserFactory
    # Whether users can sign in with their Django password. When True, a
    # usable password counts as another way to sign in, so the last provider
    # identity can be disconnected.
    password_login: bool


_KNOWN_KEYS = frozenset({"CREATE_USER", "PASSWORD_LOGIN"})


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

    password_login = raw.get("PASSWORD_LOGIN", True)
    if not isinstance(password_login, bool):
        raise ImproperlyConfigured("CROSS_AUTH['PASSWORD_LOGIN'] must be a bool")

    return CrossAuthSettings(create_user=factory, password_login=password_login)


def _reset(*, setting: str, **kwargs: object) -> None:
    if setting in {"CROSS_AUTH", "AUTH_USER_MODEL"}:
        get_settings.cache_clear()


setting_changed.connect(_reset)
