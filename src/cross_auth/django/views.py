"""Browser views for provider sign-in, linking, and disconnecting.

Every view runs Cross Auth's shared OAuth flow; this module only adapts
requests and responses and completes sign-in with ``django.contrib.auth``.
Mutations are POSTs protected by ``CsrfViewMiddleware`` (a system check
requires it); the provider callback is a GET verified by OAuth state, browser
binding, PKCE, and the OpenID Connect nonce. Each request sends
``cross_auth.django.signals`` through its own ``_Signals`` bridge.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from functools import wraps
from typing import Concatenate, Literal, ParamSpec

from cross_web import HTTPRequest
from cross_web import Response as CrossWebResponse
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth import login as django_login
from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.sessions.backends.db import SessionStore as DatabaseSessionStore
from django.core.exceptions import ImproperlyConfigured
from django.db import connections, router, transaction
from django.dispatch import Signal
from django.http import Http404, HttpRequest, HttpResponse, HttpResponseNotAllowed
from django.shortcuts import render, resolve_url
from django.utils.cache import add_never_cache_headers
from django.utils.http import url_has_allowed_host_and_scheme

from cross_auth._auth_flow import (
    AuthRequest,
    disconnect_provider,
    handle_callback,
    start_connect_flow,
    start_session_flow,
)
from cross_auth._context import Context
from cross_auth._login import require_immediate_commit, run_login
from cross_auth._storage import CommitCallback, SocialAccount, User
from cross_auth.exceptions import CrossAuthException
from cross_auth.hooks import (
    AfterLoginEvent,
    AfterOAuthDisconnectEvent,
    AfterSocialAccountCreateEvent,
    AfterSocialAccountUpdateEvent,
    AfterUserCreateEvent,
    BeforeLoginEvent,
    BeforeOAuthDisconnectEvent,
    BeforeSocialAccountCreateEvent,
    BeforeSocialAccountUpdateEvent,
    BeforeUserCreateEvent,
    HookRegistry,
)
from cross_auth.social_providers.oauth import OAuth2Provider, ValidatedUserInfo

from . import models, signals
from .backends import CrossAuthBackend
from .conf import get_settings
from .storage import DjangoAccountsStorage, DjangoSecondaryStorage, DjangoUser

BACKEND = "cross_auth.django.backends.CrossAuthBackend"

_SAMESITE: dict[str, Literal["Lax", "Strict", "None"]] = {
    "lax": "Lax",
    "strict": "Strict",
    "none": "None",
}

_P = ParamSpec("_P")
_View = Callable[Concatenate[HttpRequest, _P], HttpResponse]


def _auth_view(method: str) -> Callable[[_View[_P]], _View[_P]]:
    """Allow one HTTP method, disable caching and opt out of ATOMIC_REQUESTS.

    Each step commits on its own, so a request-wide transaction must not wrap
    these views.
    """

    def decorate(view: _View[_P]) -> _View[_P]:
        @wraps(view)
        def wrapper(
            request: HttpRequest, *args: _P.args, **kwargs: _P.kwargs
        ) -> HttpResponse:
            if request.method != method:
                return HttpResponseNotAllowed([method])
            response = view(request, *args, **kwargs)
            add_never_cache_headers(response)
            return response

        for alias in settings.DATABASES:
            wrapper = transaction.non_atomic_requests(using=alias)(wrapper)
        return wrapper

    return decorate


def _native(user: User) -> AbstractBaseUser:
    if not isinstance(user, DjangoUser):
        raise TypeError("Cross Auth's Django views need DjangoAccountsStorage users")
    return user.native


def _native_account(account: SocialAccount) -> models.SocialAccount:
    if not isinstance(account, models.SocialAccount):
        raise TypeError("Cross Auth's Django views need DjangoAccountsStorage accounts")
    return account


# Signals name flows after the views that start them.
_FLOWS: dict[str, Literal["login", "link"]] = {"session": "login", "connect": "link"}


class _Signals:
    """Sends ``cross_auth.django.signals`` for one request's provider flow.

    Core's lifecycle events reach it through hook registries built for this
    request, so receivers get the request and provider without global state.
    """

    def __init__(self, request: HttpRequest, provider: OAuth2Provider) -> None:
        self.request = request
        self.provider = provider.id
        # Set once the callback is verified; a link sends social_account_linked.
        self.flow: Literal["login", "link"] | None = None
        self.hooks = HookRegistry()
        self.hooks.register_before("user.create", self._before_user_create)
        self.hooks.register_after("user.create", self._user_created)
        self.hooks.register_before(
            "social_account.create", self._before_social_account_create
        )
        self.hooks.register_after("social_account.create", self._account_created)
        self.hooks.register_before(
            "social_account.update", self._before_social_account_update
        )
        self.hooks.register_after("social_account.update", self._account_updated)
        self.hooks.register_before("oauth.disconnect", self._before_disconnect)
        self.hooks.register_after("oauth.disconnect", self._disconnected)

    def send(self, signal: Signal, **kwargs: object) -> None:
        signal.send(
            sender=get_user_model(),
            request=self.request,
            provider=self.provider,
            **kwargs,
        )

    def verified(self, auth_request: AuthRequest, validated: ValidatedUserInfo) -> None:
        self.flow = _FLOWS[auth_request.flow]
        self.send(
            signals.before_callback,
            flow=self.flow,
            provider_user_id=validated.provider_user_id,
            email=validated.email,
            email_verified=validated.email_verified,
            user_id=auth_request.user_id,
        )

    def _before_user_create(self, event: BeforeUserCreateEvent) -> None:
        self.send(
            signals.before_user_create,
            email=event.email,
            email_verified=event.email_verified,
        )

    def _user_created(self, event: AfterUserCreateEvent) -> None:
        self.send(signals.user_created, user=_native(event.user))

    def _before_social_account_create(
        self, event: BeforeSocialAccountCreateEvent
    ) -> None:
        self.send(
            signals.before_social_account_create,
            user_id=str(event.user_id),
            provider_user_id=event.provider_user_id,
            email=event.provider_email,
            email_verified=event.provider_email_verified,
            is_login_method=event.is_login_method,
        )

    def _account_created(self, event: AfterSocialAccountCreateEvent) -> None:
        account = _native_account(event.social_account)
        self.send(signals.social_account_created, social_account=account)
        self._linked(account)

    def _before_social_account_update(
        self, event: BeforeSocialAccountUpdateEvent
    ) -> None:
        self.send(
            signals.before_social_account_update,
            social_account_id=str(event.social_account.id),
            user_id=str(event.user_id),
            provider_user_id=event.provider_user_id,
            email=event.provider_email,
            email_verified=event.provider_email_verified,
            is_login_method=event.is_login_method,
        )

    def _account_updated(self, event: AfterSocialAccountUpdateEvent) -> None:
        account = _native_account(event.social_account)
        self.send(signals.social_account_updated, social_account=account)
        self._linked(account)

    def _linked(self, account: models.SocialAccount) -> None:
        # A link callback writes exactly one account; sign-ins never link.
        if self.flow == "link":
            self.send(signals.social_account_linked, social_account=account)

    def _before_disconnect(self, event: BeforeOAuthDisconnectEvent) -> None:
        self.send(
            signals.before_social_account_disconnect,
            social_account_id=str(event.social_account.id),
            user_id=str(event.user.id),
            provider_user_id=event.social_account.provider_user_id,
        )

    def _disconnected(self, event: AfterOAuthDisconnectEvent) -> None:
        self.send(
            signals.social_account_disconnected,
            social_account=_native_account(event.social_account),
        )

    def login_hooks(self, user: DjangoUser) -> HookRegistry:
        """Return hooks that send the login signals around logging in ``user``."""

        def before(event: BeforeLoginEvent) -> None:
            self.send(signals.before_login, user_id=event.user_id, email=user.email)

        def after(event: AfterLoginEvent) -> None:
            self.send(signals.after_login, user=user.native)

        hooks = HookRegistry()
        hooks.register_before("login", before)
        hooks.register_after("login", after)
        return hooks


class DjangoLogin:
    """Completes a verified provider sign-in with ``django.contrib.auth``."""

    def __init__(self, request: HttpRequest, bridge: _Signals) -> None:
        self.request = request
        self.bridge = bridge
        session = request.session
        if not isinstance(session, DatabaseSessionStore):
            raise ImproperlyConfigured(
                "Cross Auth's Django views need database-backed sessions "
                "(SESSION_ENGINE db or cached_db)"
            )
        self.session = session
        self.alias = router.db_for_write(session.get_model_class())

    def on_commit(self, callback: CommitCallback) -> None:
        transaction.on_commit(callback, using=self.alias, robust=False)

    def login(self, user: User, *, response: CrossWebResponse) -> CrossWebResponse:
        if not isinstance(user, DjangoUser):
            raise TypeError("DjangoLogin needs users from DjangoAccountsStorage")
        native = user.native
        if not CrossAuthBackend().user_can_authenticate(native):
            raise CrossAuthException(
                "access_denied", "This account is inactive.", status_code=403
            )
        require_immediate_commit(
            self.on_commit,
            "Cross Auth's Django login must not run inside transaction.atomic",
        )

        def issue(event: BeforeLoginEvent) -> tuple[CrossWebResponse, None]:
            assert event.response is not None
            django_login(self.request, native, backend=BACKEND)
            # Persist the rotated session now, so after_login receivers see a
            # login that is stored rather than one waiting for SessionMiddleware.
            self.session.save()
            return event.response, None

        issued, _ = run_login(
            BeforeLoginEvent(
                user_id=str(native.pk),
                credential="django_session",
                max_age=None,
                metadata=None,
                response=response,
            ),
            hooks=self.bridge.login_hooks(user),
            issue=issue,
            on_commit=self.on_commit,
        )
        return issued


def _provider(provider_id: str) -> OAuth2Provider:
    provider = get_settings().providers.get(provider_id)
    if provider is None:
        raise Http404("Unknown provider")
    return provider


def _current_user(request: HttpRequest) -> DjangoUser | None:
    user = request.user
    if not isinstance(user, AbstractBaseUser) or not user.is_authenticated:
        return None
    return DjangoUser(user, password_login=get_settings().password_login)


def _default_next_url() -> str:
    return resolve_url(settings.LOGIN_REDIRECT_URL)


def _next_url(request: HttpRequest) -> str:
    """Return the POSTed ``next`` path when Django considers it safe."""
    next_url = request.POST.get("next", "")
    if next_url.startswith("/") and url_has_allowed_host_and_scheme(
        next_url,
        allowed_hosts={request.get_host()},
        require_https=request.is_secure(),
    ):
        return next_url
    return _default_next_url()


def _context(request: HttpRequest, bridge: _Signals) -> Context:
    """Build the core context, whose hooks send ``bridge``'s signals."""
    conf = get_settings()
    accounts = DjangoAccountsStorage()
    secondary = DjangoSecondaryStorage()
    for alias in {accounts.alias, secondary.alias}:
        if connections[alias].in_atomic_block:
            raise ImproperlyConfigured(
                "Cross Auth's Django views must not run inside transaction.atomic"
            )
    return Context(
        secondary_storage=secondary,
        accounts_storage=accounts,
        get_user_from_request=lambda _: _current_user(request),
        base_url=conf.base_url,
        config={
            "account_linking": conf.account_linking,
            "require_verified_email": conf.require_verified_email,
        },
        default_next_url=_default_next_url(),
        hooks=bridge.hooks,
    )


def _to_django(request: HttpRequest, response: CrossWebResponse) -> HttpResponse:
    headers = dict(response.headers or {})
    if response.status_code >= 400:
        try:
            body = json.loads(response.body or "{}")
        except json.JSONDecodeError:
            body = {}
        result = render(
            request,
            "cross_auth/error.html",
            {
                "error": body.get("error", "server_error"),
                "error_description": body.get("error_description"),
                "return_url": _default_next_url(),
            },
            status=response.status_code,
        )
    else:
        result = HttpResponse(response.body or b"", status=response.status_code)
        for name, value in headers.items():
            result[name] = value
    for cookie in response.cookies or []:
        result.set_cookie(
            cookie.name,
            cookie.value,
            max_age=cookie.max_age,
            path=cookie.path or "/",
            domain=cookie.domain,
            secure=cookie.secure,
            httponly=cookie.httponly,
            samesite=_SAMESITE[cookie.samesite],
        )
    return result


@_auth_view("POST")
def login(request: HttpRequest, provider: str) -> HttpResponse:
    """Start signing in with ``provider``; POST ``next`` to choose the target."""
    oauth_provider = _provider(provider)
    bridge = _Signals(request, oauth_provider)
    context = _context(request, bridge)
    bridge.send(signals.before_authorization, flow="login", user_id=None)
    response = start_session_flow(
        oauth_provider,
        HTTPRequest.from_django(request),
        context,
        next_url=_next_url(request),
    )
    bridge.send(signals.authorization_started, flow="login")
    return _to_django(request, response)


@_auth_view("POST")
def link(request: HttpRequest, provider: str) -> HttpResponse:
    """Connect ``provider`` to the signed-in user as another way to sign in."""
    oauth_provider = _provider(provider)
    bridge = _Signals(request, oauth_provider)
    context = _context(request, bridge)
    # Core answers a signed-out browser with 401 and stores nothing.
    if (user := _current_user(request)) is not None:
        bridge.send(signals.before_authorization, flow="link", user_id=str(user.id))
    response = start_connect_flow(
        oauth_provider,
        HTTPRequest.from_django(request),
        context,
        allow_login=True,
        next_url=_next_url(request),
    )
    if user is not None:
        bridge.send(signals.authorization_started, flow="link")
    return _to_django(request, response)


@_auth_view("GET")
def callback(request: HttpRequest, provider: str) -> HttpResponse:
    """Finish a sign-in or link when the provider redirects back."""
    oauth_provider = _provider(provider)
    bridge = _Signals(request, oauth_provider)
    response = handle_callback(
        oauth_provider,
        HTTPRequest.from_django(request),
        _context(request, bridge),
        login=DjangoLogin(request, bridge),
        on_verified=bridge.verified,
    )
    return _to_django(request, response)


@_auth_view("POST")
def disconnect(
    request: HttpRequest, provider: str, social_account_id: int
) -> HttpResponse:
    """Disconnect one of the signed-in user's identities from ``provider``."""
    oauth_provider = _provider(provider)
    response = disconnect_provider(
        oauth_provider,
        HTTPRequest.from_django(request),
        _context(request, _Signals(request, oauth_provider)),
    )
    if response.status_code == 200:
        response = CrossWebResponse.redirect(_next_url(request))
    return _to_django(request, response)
