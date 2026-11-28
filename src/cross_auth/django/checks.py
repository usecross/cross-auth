from __future__ import annotations

from typing import Any

from django.conf import settings
from django.core import checks
from django.core.exceptions import ImproperlyConfigured

from .backends import BACKEND
from .conf import get_settings

SESSION_ENGINE = "cross_auth.django.sessions"
SESSION_MIDDLEWARE = "cross_auth.django.sessions.SessionMiddleware"
_AUTHENTICATION_MIDDLEWARE = "django.contrib.auth.middleware.AuthenticationMiddleware"
_SESSION_ENGINES = {
    "django.contrib.sessions.backends.db",
    "django.contrib.sessions.backends.cached_db",
    SESSION_ENGINE,
}
# Each entry is satisfied by any one of its middleware.
_REQUIRED_MIDDLEWARE = (
    ("django.contrib.sessions.middleware.SessionMiddleware", SESSION_MIDDLEWARE),
    ("django.middleware.csrf.CsrfViewMiddleware",),
    (_AUTHENTICATION_MIDDLEWARE,),
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
                f"{', '.join(mfa_apps)} is installed: Cross Auth does not read "
                "its devices.",
                hint=(
                    "Provider sign-in does not ask for that app's second factor, "
                    "and with CROSS_AUTH['MFA'] users would be asked for Cross "
                    "Auth's own as well. Use one system: CROSS_AUTH['MFA'], or "
                    "the other app without Cross Auth sign-in."
                ),
                id="cross_auth.W001",
            )
        )
    return messages


MFA_MIDDLEWARE = "cross_auth.django.mfa.MFAMiddleware"


@checks.register(checks.Tags.security)
def check_mfa_setup(**kwargs: Any) -> list[checks.CheckMessage]:
    try:
        mfa = get_settings().mfa
    except (ImproperlyConfigured, ImportError):
        return []  # cross_auth.E001
    if mfa is None:
        return []
    messages: list[checks.CheckMessage] = []
    middleware = list(settings.MIDDLEWARE)
    sessions = [
        name
        for name in (
            SESSION_MIDDLEWARE,
            "django.contrib.sessions.middleware.SessionMiddleware",
        )
        if name in middleware
    ]
    if (
        MFA_MIDDLEWARE not in middleware
        or _AUTHENTICATION_MIDDLEWARE not in middleware
        or middleware.index(MFA_MIDDLEWARE)
        < middleware.index(_AUTHENTICATION_MIDDLEWARE)
        or any(middleware.index(MFA_MIDDLEWARE) < middleware.index(s) for s in sessions)
    ):
        messages.append(
            checks.Error(
                f"CROSS_AUTH['MFA'] needs {MFA_MIDDLEWARE!r} in MIDDLEWARE, after "
                f"{_AUTHENTICATION_MIDDLEWARE!r} and the session middleware.",
                hint=(
                    "Without it, a login that waits for its second factor "
                    "answers with the login view's own response instead of "
                    "the verify page."
                ),
                id="cross_auth.E006",
            )
        )
    if settings.SESSION_ENGINE != SESSION_ENGINE:
        messages.append(
            checks.Error(
                f"CROSS_AUTH['MFA'] needs SESSION_ENGINE = {SESSION_ENGINE!r}.",
                hint=(
                    "Turning on 2FA signs the user's other sessions out, and "
                    "2FA changes need a recent sign-in: both read Cross Auth's "
                    "sessions. Switching engines signs every user out once."
                ),
                id="cross_auth.E008",
            )
        )
    return messages


@checks.register(checks.Tags.compatibility)
def check_session_setup(**kwargs: Any) -> list[checks.CheckMessage]:
    messages: list[checks.CheckMessage] = []
    engine = settings.SESSION_ENGINE == SESSION_ENGINE
    middleware = list(settings.MIDDLEWARE)
    if engine and SESSION_MIDDLEWARE not in middleware:
        messages.append(
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
        )
    if SESSION_MIDDLEWARE in middleware and not engine:
        messages.append(
            checks.Warning(
                f"{SESSION_MIDDLEWARE!r} is in MIDDLEWARE, but SESSION_ENGINE is "
                f"{settings.SESSION_ENGINE!r}.",
                hint=(
                    f"Set SESSION_ENGINE = {SESSION_ENGINE!r}; with other engines "
                    "the middleware records nothing."
                ),
                id="cross_auth.W003",
            )
        )
    if (
        SESSION_MIDDLEWARE in middleware
        and _AUTHENTICATION_MIDDLEWARE in middleware
        and middleware.index(SESSION_MIDDLEWARE)
        > middleware.index(_AUTHENTICATION_MIDDLEWARE)
    ):
        messages.append(
            checks.Error(
                f"{SESSION_MIDDLEWARE!r} must come before "
                f"{_AUTHENTICATION_MIDDLEWARE!r} in MIDDLEWARE.",
                hint=(
                    "AuthenticationMiddleware reads request.session, which the "
                    "session middleware sets, so every request fails."
                ),
                id="cross_auth.E005",
            )
        )
    return messages
