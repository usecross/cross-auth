"""Settings for the Cross Auth Django example.

Based on ``django-admin startproject`` with the additions from the Django
tutorial: the Cross Auth app, its authentication backend, Google as a
provider, and login redirects.
"""

import os
from pathlib import Path

from cross_auth.social_providers.google import GoogleProvider

BASE_DIR = Path(__file__).resolve().parent.parent

# Development defaults; see the tutorial's production checklist.
SECRET_KEY = os.environ.get(
    "DJANGO_SECRET_KEY", "django-insecure-example-key-do-not-use-in-production"
)
DEBUG = True
ALLOWED_HOSTS = ["127.0.0.1", "localhost"]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "cross_inertia.django",
    "cross_auth.django",
    "core.apps.CoreConfig",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    # Cross Auth's sessions, which two-factor authentication needs.
    "cross_auth.django.sessions.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    # Sends logins that wait for a second factor to the verify page.
    "cross_auth.django.mfa.MFAMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "cross_inertia.django.InertiaMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"

# Inertia: the pages are React components in ../frontend, shared with the
# FastAPI example. `bun run build` there writes dist/, served as
# static/build/. With DEBUG, runserver also starts the Vite dev server.
FRONTEND_DIR = BASE_DIR.parent / "frontend"
STATICFILES_DIRS = [("build", FRONTEND_DIR / "dist")]

CROSS_INERTIA = {
    "LAYOUT": "core/app.html",
    "VITE_ENTRY": "src/app.tsx",
    "VITE_PORT": 5174,
    "VITE_BASE": "/static/build/",
    "VITE_COMMAND": ["bun", "--cwd", str(FRONTEND_DIR), "run", "dev"],
    "MANIFEST_PATH": FRONTEND_DIR / "dist" / ".vite" / "manifest.json",
    "SHARE": "core.inertia.share",
}

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# Cross Auth

AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",
    "cross_auth.django.backends.CrossAuthBackend",
]

SESSION_ENGINE = "cross_auth.django.sessions"

LOGIN_URL = "login"
LOGIN_REDIRECT_URL = "home"
LOGOUT_REDIRECT_URL = "home"

CROSS_AUTH = {
    "PROVIDERS": [
        GoogleProvider(
            client_id=os.environ["GOOGLE_CLIENT_ID"],
            client_secret=os.environ["GOOGLE_CLIENT_SECRET"],
        ),
    ],
    # Two-factor authentication with an authenticator app. Users turn it on at
    # /settings/2fa/; secrets are encrypted with keys derived from SECRET_KEY.
    "MFA": {
        "issuer": "Cross Auth Django example",
        # Sign-ins that wait for a code go to the example's own page.
        "verify_url": "two_factor_verify",
    },
}
