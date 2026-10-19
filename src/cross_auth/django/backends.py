from __future__ import annotations

from typing import Any

from django.contrib.auth.backends import ModelBackend
from django.http import HttpRequest


class CrossAuthBackend(ModelBackend):
    """Authentication backend recorded on sessions started by provider sign-in.

    It never authenticates credentials: ``authenticate()`` always returns
    None, so nothing sent in a request can log a user in through it. Cross Auth
    logs users in only after verifying a provider identity. Like
    ``ModelBackend``, it rejects inactive users on later requests and grants
    the user's model and group permissions.
    """

    def authenticate(
        self,
        request: HttpRequest | None,
        username: str | None = None,
        password: str | None = None,
        **kwargs: Any,
    ) -> None:
        return None
