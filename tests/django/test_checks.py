import subprocess
import sys

import pytest
from django.core import checks
from django.test import override_settings

from cross_auth.django.checks import check_settings


def test_valid_settings_pass() -> None:
    assert check_settings() == []


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ({"PASSWORD_LOGN": False}, "Unknown CROSS_AUTH setting(s): PASSWORD_LOGN"),
        ({"PASSWORD_LOGIN": "no"}, "PASSWORD_LOGIN'] must be a bool"),
        ({"CREATE_USER": "tests.django.missing.create"}, "No module named"),
        ({"CREATE_USER": print}, "must be the dotted path of a function"),
        ({"CREATE_USER": "tests.django.settings.SECRET_KEY"}, "is not callable"),
    ],
)
def test_invalid_settings_are_errors(value: object, message: str) -> None:
    with override_settings(CROSS_AUTH=value):
        errors = check_settings()

    assert [error.id for error in errors] == ["cross_auth.E001"]
    assert errors[0].level == checks.ERROR
    assert message in errors[0].msg


def test_core_imports_without_django() -> None:
    code = (
        "import sys, cross_auth, cross_auth.social_providers.google; "
        "assert not any(name == 'django' or name.startswith('django.') "
        "for name in sys.modules), 'core imported Django'"
    )
    subprocess.run([sys.executable, "-c", code], check=True)


def test_settings_can_import_providers_before_apps_are_ready() -> None:
    code = (
        "import django.conf, cross_auth.django, cross_auth.django.signals, "
        "cross_auth.social_providers.google; "
        "from django.apps import apps; assert not apps.ready"
    )
    subprocess.run([sys.executable, "-c", code], check=True)


def _login_setup_ids() -> list[str]:
    from cross_auth.django.checks import check_login_setup

    return [message.id or "" for message in check_login_setup()]


def test_login_setup_passes() -> None:
    assert _login_setup_ids() == []


def test_backend_is_required() -> None:
    with override_settings(
        AUTHENTICATION_BACKENDS=["django.contrib.auth.backends.ModelBackend"]
    ):
        assert _login_setup_ids() == ["cross_auth.E002"]


def test_database_sessions_are_required() -> None:
    with override_settings(
        SESSION_ENGINE="django.contrib.sessions.backends.signed_cookies"
    ):
        assert _login_setup_ids() == ["cross_auth.E003"]


def test_session_auth_and_csrf_middleware_are_required() -> None:
    with override_settings(MIDDLEWARE=["django.middleware.common.CommonMiddleware"]):
        assert _login_setup_ids() == ["cross_auth.E004"]


def test_mfa_apps_warn(monkeypatch: pytest.MonkeyPatch) -> None:
    from django.conf import settings

    # Only the setting is read; loading the app itself is not needed.
    monkeypatch.setattr(
        settings,
        "INSTALLED_APPS",
        [*settings.INSTALLED_APPS, "django_otp.plugins.otp_totp"],
    )

    assert _login_setup_ids() == ["cross_auth.W001"]


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ({"PROVIDERS": "google"}, "must be a list"),
        ({"PROVIDERS": [object()]}, "provider instances"),
        ({"ACCOUNT_LINKING": {"allow_shared_connections": True}}, "Unsupported"),
        ({"ACCOUNT_LINKING": {"enabled": "yes"}}, "['enabled'] must be a bool"),
        # Receivers of cross_auth.django.signals replace a hook registry.
        ({"HOOKS": "core.auth_hooks.hooks"}, "Unknown CROSS_AUTH setting(s): HOOKS"),
        ({"BASE_URL": "example.com"}, "must be an origin"),
    ],
)
def test_invalid_login_settings_are_errors(value: object, message: str) -> None:
    with override_settings(CROSS_AUTH=value):
        errors = check_settings()

    assert len(errors) == 1
    assert message in errors[0].msg


def test_duplicate_providers_are_errors() -> None:
    from cross_auth.social_providers.google import GoogleProvider

    google = GoogleProvider(client_id="a", client_secret="b")
    with override_settings(CROSS_AUTH={"PROVIDERS": [google, google]}):
        errors = check_settings()

    assert "more than once" in errors[0].msg


@pytest.mark.parametrize("value", [-1, 1.5, "60", True, 31_536_001, 10**20])
def test_session_activity_interval_must_be_seconds(value: object) -> None:
    with override_settings(CROSS_AUTH={"SESSION_ACTIVITY_INTERVAL": value}):
        errors = check_settings()

    assert [error.id for error in errors] == ["cross_auth.E001"]
    assert "SESSION_ACTIVITY_INTERVAL'] must be a number of seconds" in errors[0].msg


def test_session_activity_interval_defaults_to_a_minute() -> None:
    from datetime import timedelta

    from cross_auth.django.conf import get_settings

    assert get_settings().session_activity_interval == timedelta(minutes=1)
    with override_settings(CROSS_AUTH={"SESSION_ACTIVITY_INTERVAL": 0}):
        assert get_settings().session_activity_interval == timedelta(0)
    with override_settings(CROSS_AUTH={"SESSION_ACTIVITY_INTERVAL": 31_536_000}):
        assert get_settings().session_activity_interval == timedelta(days=365)


DJANGO_SESSION_MIDDLEWARE = "django.contrib.sessions.middleware.SessionMiddleware"
SESSION_MIDDLEWARE = "cross_auth.django.sessions.SessionMiddleware"


def _with_session_middleware(name: str) -> list[str]:
    from django.conf import settings

    return [
        name if entry == DJANGO_SESSION_MIDDLEWARE else entry
        for entry in settings.MIDDLEWARE
    ]


def _session_setup_ids() -> list[str]:
    from cross_auth.django.checks import check_session_setup

    return [message.id or "" for message in check_session_setup()]


def test_cross_auth_sessions_pass() -> None:
    with override_settings(
        SESSION_ENGINE="cross_auth.django.sessions",
        MIDDLEWARE=_with_session_middleware(SESSION_MIDDLEWARE),
    ):
        assert _login_setup_ids() == []
        assert _session_setup_ids() == []


def test_django_sessions_pass() -> None:
    assert _session_setup_ids() == []


def test_session_engine_without_its_middleware_warns() -> None:
    with override_settings(SESSION_ENGINE="cross_auth.django.sessions"):
        assert _session_setup_ids() == ["cross_auth.W002"]


def test_session_middleware_without_its_engine_warns() -> None:
    with override_settings(MIDDLEWARE=_with_session_middleware(SESSION_MIDDLEWARE)):
        assert _session_setup_ids() == ["cross_auth.W003"]


def test_session_middleware_after_authentication_middleware_is_an_error() -> None:
    authentication = "django.contrib.auth.middleware.AuthenticationMiddleware"
    middleware = [
        name
        for name in _with_session_middleware(SESSION_MIDDLEWARE)
        if name != authentication
    ]
    middleware.insert(middleware.index(SESSION_MIDDLEWARE), authentication)

    with override_settings(
        SESSION_ENGINE="cross_auth.django.sessions", MIDDLEWARE=middleware
    ):
        assert _session_setup_ids() == ["cross_auth.E005"]
