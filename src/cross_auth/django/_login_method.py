"""How a Django session signed in through Cross Auth."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from django.http import HttpRequest

# Framework-owned session keys start with an underscore, like Django's own
# ``_auth_user_id``.
LOGIN_METHOD_SESSION_KEY = "_cross_auth_login_method"


def get_login_method(request: HttpRequest) -> str | None:
    """Return how the request's session signed in through Cross Auth.

    The provider's id (such as ``"google"``) for a session a Cross Auth
    provider sign-in started, and ``None`` for any other login, such as
    Django's password login.
    """
    return request.session.get(LOGIN_METHOD_SESSION_KEY)


def forget_login_method(
    sender: object, request: HttpRequest | None = None, **kwargs: Any
) -> None:
    """``user_logged_in`` receiver that drops the stored login method.

    Django keeps a session's data when the same user logs in again, so without
    this a later password login would keep the provider a sign-in recorded.
    Cross Auth's own login stores its value after ``login()`` returns.
    """
    if request is not None:
        request.session.pop(LOGIN_METHOD_SESSION_KEY, None)
