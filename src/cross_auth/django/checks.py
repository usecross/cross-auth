from __future__ import annotations

from typing import Any

from django.conf import settings
from django.core import checks
from django.core.exceptions import ImproperlyConfigured

from .conf import get_settings

BACKEND = "cross_auth.django.backends.CrossAuthBackend"
SESSION_ENGINE = "cross_auth.django.sessions"
SESSION_MIDDLEWARE = "cross_auth.django.sessions.SessionMiddleware"
_SESSION_ENGINES = {
    "django.contrib.sessions.backends.db",
    "django.contrib.sessions.backends.cached_db",
    SESSION_ENGINE,
}
# Each entry is satisfied by any one of its middleware.
_REQUIRED_MIDDLEWARE = (
    ("django.contrib.sessions.middleware.SessionMiddleware", SESSION_MIDDLEWARE),
    ("django.middleware.csrf.CsrfViewMiddleware",),
    ("django.contrib.auth.middleware.AuthenticationMiddleware",),
)
# Apps whose presence suggests sign-in requires another factor. Provider
# sign-in calls django.contrib.auth.login() directly and would skip it.
_MFA_APPS = ("django_otp", "two_factor", "allauth.mfa", "mfa")


@checks.register(checks.Tags.compatibility)
def check_settings(**kwargs: Any) -> list[checks.CheckMessage]:
    try:
        get_settings()
    except (ImproperlyConfigured, ImportError) as error:
        return [checks.Error(str(error), id="cross_auth.E001")]
    return []


@checks.register(checks.Tags.security)
def check_login_setup(**kwargs: Any) -> list[checks.CheckMessage]:
    messages: list[checks.CheckMessage] = []
    if BACKEND not in settings.AUTHENTICATION_BACKENDS:
        messages.append(
            checks.Error(
                f"Add {BACKEND!r} to AUTHENTICATION_BACKENDS.",
                hint=(
                    "Provider sign-ins are stored with this backend; without it "
                    "Django cannot restore request.user on later requests."
                ),
                id="cross_auth.E002",
            )
        )
    if settings.SESSION_ENGINE not in _SESSION_ENGINES:
        messages.append(
            checks.Error(
                "Cross Auth's Django views need database-backed sessions.",
                hint=(
                    "Set SESSION_ENGINE to the db or cached_db backend, or to "
                    f"{SESSION_ENGINE!r}."
                ),
                id="cross_auth.E003",
            )
        )
    missing = [
        names[0]
        for names in _REQUIRED_MIDDLEWARE
        if not any(name in settings.MIDDLEWARE for name in names)
    ]
    if missing:
        messages.append(
            checks.Error(
                f"Add {', '.join(missing)} to MIDDLEWARE.",
                id="cross_auth.E004",
            )
        )
    mfa_apps = [
        app
        for app in settings.INSTALLED_APPS
        if app in _MFA_APPS or app.startswith(tuple(f"{name}." for name in _MFA_APPS))
    ]
    if mfa_apps:
        messages.append(
            checks.Warning(
                "Provider sign-in logs users in without your multi-factor step.",
                hint=(
                    f"{', '.join(mfa_apps)} is installed. Do not enable Cross Auth "
                    "sign-in where users must complete another factor; silence "
                    "this with SILENCED_SYSTEM_CHECKS only if MFA is optional."
                ),
                id="cross_auth.W001",
            )
        )
    return messages


@checks.register(checks.Tags.compatibility)
def check_session_setup(**kwargs: Any) -> list[checks.CheckMessage]:
    engine = settings.SESSION_ENGINE == SESSION_ENGINE
    middleware = SESSION_MIDDLEWARE in settings.MIDDLEWARE
    if engine and not middleware:
        return [
            checks.Warning(
                f"SESSION_ENGINE is {SESSION_ENGINE!r}, but its SessionMiddleware "
                "is not in MIDDLEWARE.",
                hint=(
                    "Replace django.contrib.sessions.middleware.SessionMiddleware "
                    f"with {SESSION_MIDDLEWARE!r}, or sessions record no user "
                    "agent, IP or recent activity."
                ),
                id="cross_auth.W002",
            )
        ]
    if middleware and not engine:
        return [
            checks.Warning(
                f"{SESSION_MIDDLEWARE!r} is in MIDDLEWARE, but SESSION_ENGINE is "
                f"{settings.SESSION_ENGINE!r}.",
                hint=(
                    f"Set SESSION_ENGINE = {SESSION_ENGINE!r}; with other engines "
                    "the middleware records nothing."
                ),
                id="cross_auth.W003",
            )
        ]
    return []
