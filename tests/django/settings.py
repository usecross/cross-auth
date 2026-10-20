"""Django settings for the integration tests.

``CROSS_AUTH_TEST_DATABASE`` selects ``sqlite`` (default) or ``postgres``; the
PostgreSQL run starts a disposable container. ``CROSS_AUTH_TEST_USER_MODEL``
selects Django's ``default`` user or a ``custom`` UUID user with its own
manager and required fields.
"""

import atexit
import os
import tempfile

from cross_auth.social_providers.google import GoogleProvider


class WorkspaceProvider(GoogleProvider):
    """A second provider, to test callbacks reaching the wrong one."""

    id = "workspace"


DATABASE = os.environ.get("CROSS_AUTH_TEST_DATABASE", "sqlite")
USER_MODEL = os.environ.get("CROSS_AUTH_TEST_USER_MODEL", "default")

SECRET_KEY = "cross-auth-tests"
USE_TZ = True
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
ALLOWED_HOSTS = ["testserver", "localhost"]
ROOT_URLCONF = "tests.django.urls"

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "cross_auth.django",
    "tests.django.testapp",
]

AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",
    "cross_auth.django.backends.CrossAuthBackend",
]
LOGIN_REDIRECT_URL = "/"
LOGIN_URL = "/accounts/login/"
LOGOUT_REDIRECT_URL = "/"

CROSS_AUTH: dict[str, object] = {
    "PROVIDERS": [
        GoogleProvider(client_id="test-client-id", client_secret="test-secret"),
        WorkspaceProvider(client_id="test-client-id", client_secret="test-secret"),
    ],
}

if USER_MODEL == "custom":
    INSTALLED_APPS.append("tests.django.custom_user")
    AUTH_USER_MODEL = "custom_user.User"
    CROSS_AUTH["CREATE_USER"] = "tests.django.custom_user.models.create_user"
elif USER_MODEL != "default":
    raise ValueError(f"Unknown CROSS_AUTH_TEST_USER_MODEL {USER_MODEL!r}")

MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
]

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
            ]
        },
    }
]

PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]

if DATABASE == "postgres":
    from testcontainers.postgres import PostgresContainer

    _container = PostgresContainer("postgres:16-alpine", driver=None)
    _container.start()
    atexit.register(_container.stop)
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "HOST": _container.get_container_host_ip(),
            "PORT": _container.get_exposed_port(5432),
            "NAME": _container.dbname,
            "USER": _container.username,
            "PASSWORD": _container.password,
        }
    }
elif DATABASE == "sqlite":
    # Threads need a file database to see each other's commits.
    _directory = tempfile.mkdtemp(prefix="cross-auth-django-")
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": os.path.join(_directory, "db.sqlite3"),
            "OPTIONS": {"timeout": 20},
            "TEST": {"NAME": os.path.join(_directory, "test.sqlite3")},
        }
    }
else:
    raise ValueError(f"Unknown CROSS_AUTH_TEST_DATABASE {DATABASE!r}")
