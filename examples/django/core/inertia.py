from typing import Any

from django.http import HttpRequest
from django.middleware.csrf import get_token
from django.urls import reverse


def share(request: HttpRequest) -> dict[str, Any]:
    """Props every page receives; see frontend/src/pages/django/shared.ts."""
    user = request.user
    return {
        # The pages' forms are plain posts, so they carry Django's token.
        "csrf_token": get_token(request),
        "user": {"username": user.get_username()} if user.is_authenticated else None,
        "urls": {
            "home": reverse("home"),
            "profile": reverse("profile"),
            "password_login": reverse("login"),
            "logout": reverse("logout"),
            "google_login": reverse("cross_auth:login", args=["google"]),
            "google_link": reverse("cross_auth:link", args=["google"]),
        },
    }
