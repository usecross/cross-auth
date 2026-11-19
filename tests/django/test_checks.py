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
        ({"SESSION_STORE_IP": "no"}, "SESSION_STORE_IP'] must be a bool"),
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


def test_session_activity_interval_defaults_to_five_minutes() -> None:
    from datetime import timedelta

    from cross_auth.django.conf import get_settings

    assert get_settings().session_activity_interval == timedelta(minutes=5)
    with override_settings(CROSS_AUTH={"SESSION_ACTIVITY_INTERVAL": 0}):
        assert get_settings().session_activity_interval == timedelta(0)
    with override_settings(CROSS_AUTH={"SESSION_ACTIVITY_INTERVAL": 31_536_000}):
        assert get_settings().session_activity_interval == timedelta(days=365)


GET_CLIENT = "tests.django.clients.get_client"


def test_the_oauth_server_is_off_by_default() -> None:
    from cross_auth.django.conf import get_settings

    assert get_settings().oauth_server is None


def test_oauth_server_defaults() -> None:
    from cross_auth.django.conf import get_settings

    from .clients import get_client

    with override_settings(CROSS_AUTH={"OAUTH_SERVER": {"get_client": GET_CLIENT}}):
        assert check_settings() == []
        oauth_server = get_settings().oauth_server

    assert oauth_server is not None
    assert oauth_server.get_client is get_client
    # A day, and not extended by use: core's defaults.
    assert oauth_server.token_max_age == 86400
    assert oauth_server.token_update_age is None


@pytest.mark.parametrize(
    ("options", "ages"),
    [
        ({"token_max_age": 1}, (1, None)),
        ({"token_max_age": 2592000, "token_update_age": 0}, (2592000, 0)),
        ({"token_update_age": 3600}, (86400, 3600)),
        ({"token_update_age": None}, (86400, None)),
    ],
)
def test_oauth_server_token_ages(
    options: dict[str, object], ages: tuple[int, int | None]
) -> None:
    from cross_auth.django.conf import get_settings

    value = {"OAUTH_SERVER": {"get_client": GET_CLIENT, **options}}
    with override_settings(CROSS_AUTH=value):
        oauth_server = get_settings().oauth_server

    assert oauth_server is not None
    assert (oauth_server.token_max_age, oauth_server.token_update_age) == ages


def test_the_oauth_server_needs_time_zone_support() -> None:
    value = {"OAUTH_SERVER": {"get_client": GET_CLIENT}}
    with override_settings(CROSS_AUTH=value, USE_TZ=False):
        errors = check_settings()
    with override_settings(CROSS_AUTH={}, USE_TZ=False):
        without = check_settings()

    assert [error.id for error in errors] == ["cross_auth.E001"]
    assert errors[0].msg == "CROSS_AUTH['OAUTH_SERVER'] needs USE_TZ = True"
    assert without == []


@pytest.mark.parametrize(
    ("value", "message"),
    [
        (GET_CLIENT, "['OAUTH_SERVER'] must be a dict"),
        ({}, "['get_client'] must be the dotted path of a function"),
        ({"get_client": print}, "['get_client'] must be the dotted path"),
        ({"get_client": "tests.django.missing.get_client"}, "No module named"),
        ({"get_client": "tests.django.clients.SPA_REDIRECT"}, "is not callable"),
        (
            {"get_client": GET_CLIENT, "password_grant": True},
            "Unsupported CROSS_AUTH['OAUTH_SERVER'] key(s): password_grant",
        ),
        ({"get_client": GET_CLIENT, "token_max_age": 0}, "an int from 1 to"),
        ({"get_client": GET_CLIENT, "token_max_age": None}, "an int from 1 to"),
        ({"get_client": GET_CLIENT, "token_max_age": True}, "['token_max_age']"),
        ({"get_client": GET_CLIENT, "token_max_age": 3600.0}, "['token_max_age']"),
        ({"get_client": GET_CLIENT, "token_max_age": 10**10}, "['token_max_age']"),
        ({"get_client": GET_CLIENT, "token_update_age": -1}, "an int from 0 to"),
        ({"get_client": GET_CLIENT, "token_update_age": "1"}, "or None"),
    ],
)
def test_invalid_oauth_server_settings_are_errors(value: object, message: str) -> None:
    with override_settings(CROSS_AUTH={"OAUTH_SERVER": value}):
        errors = check_settings()

    assert [error.id for error in errors] == ["cross_auth.E001"]
    assert message in errors[0].msg


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
