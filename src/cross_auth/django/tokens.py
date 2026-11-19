"""Authenticate requests that carry a bearer token from the OAuth server.

With ``CROSS_AUTH["OAUTH_SERVER"]`` set, the token view gives your SPA and
native clients a bearer token. Your API views check it with
``authenticate_bearer``::

    from cross_auth.django.tokens import authenticate_bearer

    def profile(request):
        authenticated = authenticate_bearer(request)
        if authenticated is None:
            return JsonResponse({"error": "invalid_token"}, status=401)
        return JsonResponse({"email": authenticated.user.email})

A token's session is a row of ``cross_auth.django.models.Session``. It is
not a Django session: it sets no cookie and ``request.user`` stays as it was.
"""

from __future__ import annotations

from dataclasses import dataclass

from cross_web import HTTPRequest
from django.contrib.auth.base_user import AbstractBaseUser
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpRequest

from cross_auth._session import (
    SessionConfig,
    authenticate_session_token,
    get_bearer_token,
)
from cross_auth._storage import User

from .backends import CrossAuthBackend
from .conf import CrossAuthSettings, get_settings
from .storage import (
    DjangoAccountsStorage,
    DjangoSessionRecord,
    DjangoSessionStorage,
    DjangoUser,
)


@dataclass(frozen=True)
class AuthenticatedToken:
    """The user and session of a request's bearer token."""

    user: AbstractBaseUser
    # ``session.client_id`` is the OAuth client the token was issued to, and
    # ``session.id`` names the session in lists and when revoking it.
    session: DjangoSessionRecord


def _session_config(conf: CrossAuthSettings) -> SessionConfig:
    """Core's session settings for the OAuth server's bearer tokens."""
    oauth_server = conf.oauth_server
    assert oauth_server is not None

    return {
        "max_age": oauth_server.token_max_age,
        "update_age": oauth_server.token_update_age,
        "activity_interval": int(conf.session_activity_interval.total_seconds()),
        "store_ip": conf.session_store_ip,
    }


def _can_authenticate(user: User) -> bool:
    """Django's rule for who may sign in: by default, active users."""
    if not isinstance(user, DjangoUser):
        raise TypeError("Cross Auth's Django tokens need DjangoAccountsStorage users")

    return CrossAuthBackend().user_can_authenticate(user.native)


def authenticate_bearer(request: HttpRequest) -> AuthenticatedToken | None:
    """Return the user and session of the request's ``Authorization: Bearer`` token.

    Returns ``None`` without a bearer token, for a token that is unknown,
    expired or revoked, and for a user who may no longer sign in (an inactive
    one, by default). Using a token records its session's activity, as
    ``CROSS_AUTH["SESSION_ACTIVITY_INTERVAL"]`` sets, and extends the session
    when ``token_update_age`` is set. Session cookies are ignored.
    """
    conf = get_settings()
    if conf.oauth_server is None:
        raise ImproperlyConfigured(
            "authenticate_bearer needs CROSS_AUTH['OAUTH_SERVER'], which issues "
            "the tokens"
        )

    token = get_bearer_token(HTTPRequest.from_django(request))
    if token is None:
        return None

    authenticated = authenticate_session_token(
        token,
        DjangoSessionStorage(),
        DjangoAccountsStorage(),
        _session_config(conf),
        user_can_authenticate=_can_authenticate,
    )
    if authenticated is None:
        return None

    user = authenticated.user
    session = authenticated.session
    if not isinstance(user, DjangoUser) or not isinstance(session, DjangoSessionRecord):
        raise TypeError("Cross Auth's Django tokens need the Django storages")

    return AuthenticatedToken(user=user.native, session=session)
