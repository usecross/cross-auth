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
        "import django.conf, cross_auth.django, cross_auth.social_providers.google; "
        "from django.apps import apps; assert not apps.ready"
    )
    subprocess.run([sys.executable, "-c", code], check=True)
