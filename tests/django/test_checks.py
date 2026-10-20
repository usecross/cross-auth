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
