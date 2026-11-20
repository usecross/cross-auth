"""Browser views for provider sign-in, linking, and disconnecting, and the
OAuth server's views for SPA and native clients.

Every view runs Cross Auth's shared OAuth flow; this module only adapts
requests and responses and completes sign-in with ``django.contrib.auth``.
Mutations are POSTs protected by ``CsrfViewMiddleware`` (a system check
requires it); the provider callback is a GET verified by OAuth state, browser
binding, PKCE, and the OpenID Connect nonce. Each request sends
``cross_auth.django.signals`` through its own ``_Signals`` bridge.

The OAuth server's views exist with ``CROSS_AUTH["OAUTH_SERVER"]``; without
it they answer "not found". ``authorize`` starts a sign-in that ends at the
client's redirect URI with a one-time code. ``token`` and ``logout`` are
called by the client's own code, from another origin or a native app: they
are exempt from CSRF checks and read no cookie. The token and every OAuth
error they answer with are JSON; a logout that succeeds has no body.

A receiver that refuses a step of a client's sign-in with
``PermissionDenied`` does not get Django's 403 page, which would strand the
user in the client's sign-in browser. The refusal goes to the client as
``access_denied``: at its redirect URI from ``authorize`` and the callback,
and as JSON from ``token`` and ``logout``.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from functools import wraps
from typing import Concatenate, Literal, ParamSpec, Protocol

from cross_web import HTTPRequest
from cross_web import Response as CrossWebResponse
from cross_web.request._django import DjangoHTTPRequestAdapter
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth import login as django_login
from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.sessions.backends.db import SessionStore as DatabaseSessionStore
from django.core.exceptions import ImproperlyConfigured, PermissionDenied
from django.db import connections, router, transaction
from django.dispatch import Signal
from django.http import Http404, HttpRequest, HttpResponse, HttpResponseNotAllowed
from django.shortcuts import render, resolve_url
from django.utils.cache import add_never_cache_headers
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.csrf import csrf_exempt

from cross_auth._authorization import AuthRequest
from cross_auth._auth_flow import (
    disconnect_provider,
    handle_callback,
    start_connect_flow,
    start_session_flow,
    start_token_flow,
)
from cross_auth._auth_flow import logout as revoke_bearer_session
from cross_auth._config import Config
from cross_auth._context import Context
from cross_auth._issuer import Issuer
from cross_auth._login import require_immediate_commit, run_login
from cross_auth._oauth_server import OAuthServer
from cross_auth._storage import CommitCallback, SocialAccount, User
from cross_auth.exceptions import CrossAuthException
from cross_auth.hooks import (
    AfterLoginEvent,
    AfterLogoutEvent,
    AfterOAuthAuthorizeEvent,
    AfterOAuthDisconnectEvent,
    AfterSocialAccountCreateEvent,
    AfterSocialAccountUpdateEvent,
    AfterUserCreateEvent,
    BeforeLoginEvent,
    BeforeLogoutEvent,
    BeforeOAuthAuthorizeEvent,
    BeforeOAuthDisconnectEvent,
    BeforeSocialAccountCreateEvent,
    BeforeSocialAccountUpdateEvent,
    BeforeUserCreateEvent,
    HookRegistry,
)
from cross_auth.social_providers.oauth import OAuth2Provider, ValidatedUserInfo
from cross_auth.utils._response import Response as FlowResponse

from . import models, signals
from .backends import BACKEND, CrossAuthBackend
from .conf import get_settings
from .sessions import LOGIN_METHOD_SESSION_KEY, SessionStore
from .storage import (
    DjangoAccountsStorage,
    DjangoSecondaryStorage,
    DjangoSessionRecord,
    DjangoSessionStorage,
    DjangoUser,
)
from .tokens import _can_authenticate, _session_config

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


_Flow = Literal["login", "link", "authorize"]
# Signals name flows after the views that start them.
_FLOWS: dict[str, _Flow] = {
    "session": "login",
    "connect": "link",
    "token": "authorize",
}
_INACTIVE = "This account is inactive."


def _refused(error: PermissionDenied) -> CrossAuthException:
    """A receiver's refusal, as Cross Auth's flows report one to an OAuth client.

    Core turns it into ``access_denied`` at the client's redirect URI or in
    JSON, where Django's 403 page would be no use to the client.
    """
    return CrossAuthException("access_denied", _reason(error), status_code=403)


def _reason(error: PermissionDenied) -> str:
    return str(error) or "Permission denied"


class _Signals:
    """Sends ``cross_auth.django.signals`` for one request's provider flow.

    Core's lifecycle events reach it through hook registries built for this
    request, so receivers get the request and provider without global state.
    """

    def __init__(self, request: HttpRequest, provider: OAuth2Provider) -> None:
        self.request = request
        self.provider = provider.id
        # Set once the callback is verified; a link sends social_account_linked.
        self.flow: _Flow | None = None
        # Where a client's sign-in reports a refusal: its redirect URI and
        # state, once the callback is verified to belong to one.
        self.client: tuple[str, str | None] | None = None
        self.hooks = HookRegistry()
        # Only the authorize view's flow runs these two.
        self.hooks.register_before("oauth.authorize", self._before_authorize)
        self.hooks.register_after("oauth.authorize", self._authorize_started)
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

    def _before_authorize(self, event: BeforeOAuthAuthorizeEvent) -> None:
        try:
            self.send(signals.before_authorization, flow="authorize", user_id=None)
        except PermissionDenied as error:
            # Core sends it to the client's redirect URI, which it has just
            # checked against the client's registration.
            raise _refused(error) from error

    def _authorize_started(self, event: AfterOAuthAuthorizeEvent) -> None:
        self.send(signals.authorization_started, flow="authorize")

    def verified(self, auth_request: AuthRequest, validated: ValidatedUserInfo) -> None:
        self.flow = _FLOWS[auth_request.flow]
        if auth_request.flow == "token" and auth_request.client_redirect_uri:
            # Core checked this URI against the client's registration before
            # it exchanged the provider's code.
            self.client = (auth_request.client_redirect_uri, auth_request.client_state)
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

    def refusal(self, error: PermissionDenied) -> CrossWebResponse:
        """Answer a refusal raised while the callback completed a sign-in.

        A client's sign-in sends it to the client. Any other flow keeps
        Django's 403 response: the exception is raised again.
        """
        if self.client is None:
            raise error
        redirect_uri, state = self.client
        return FlowResponse.error_redirect(
            redirect_uri,
            error="access_denied",
            error_description=_reason(error),
            state=state,
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


class _TokenSignals:
    """Sends the login signals around the bearer token the token view issues.

    Core runs its ``login`` hooks there, once the client exchanges its code,
    so that is when ``before_login`` can still refuse the user.
    """

    def __init__(self, request: HttpRequest) -> None:
        self.request = request
        self.user: DjangoUser | None = None
        self.hooks = HookRegistry()
        self.hooks.register_before("login", self._before_login)
        self.hooks.register_after("login", self._after_login)

    def _before_login(self, event: BeforeLoginEvent) -> None:
        user = DjangoAccountsStorage().find_user_by_id(event.user_id)
        if user is None:
            raise CrossAuthException(
                "access_denied", "Sign-in is not allowed", status_code=403
            )
        self.user = user
        try:
            signals.before_login.send(
                sender=get_user_model(),
                request=self.request,
                provider=event.login_method,
                user_id=event.user_id,
                email=user.email,
            )
        except PermissionDenied as error:
            raise _refused(error) from error

    def _after_login(self, event: AfterLoginEvent) -> None:
        assert self.user is not None
        signals.after_login.send(
            sender=get_user_model(),
            request=self.request,
            provider=event.login_method,
            user=self.user.native,
        )


class _LogoutSignals:
    """Sends the session signals around the logout view revoking tokens."""

    def __init__(self, request: HttpRequest) -> None:
        self.request = request
        self.hooks = HookRegistry()
        self.hooks.register_before("logout", self._before_logout)
        self.hooks.register_after("logout", self._after_logout)

    @staticmethod
    def _named(
        record: object, scope: Literal["current", "all"]
    ) -> tuple[DjangoSessionRecord, str, str | None]:
        """Return the record with the signals' ``scope`` and ``session_id``."""
        if not isinstance(record, DjangoSessionRecord):
            raise TypeError("Cross Auth's Django views need DjangoSessionStorage")
        if scope == "all":
            return record, "all", None
        return record, "one", str(record.id)

    def _before_logout(self, event: BeforeLogoutEvent) -> None:
        if event.session_record is None:
            # No token, or one that is unknown, expired or already revoked.
            return
        record, scope, session_id = self._named(event.session_record, event.scope)
        try:
            signals.before_session_revoke.send(
                sender=get_user_model(),
                request=self.request,
                user_id=str(record.user_id),
                scope=scope,
                session_id=session_id,
            )
        except PermissionDenied as error:
            raise _refused(error) from error

    def _after_logout(self, event: AfterLogoutEvent) -> None:
        record, scope, session_id = self._named(event.session_record, event.scope)
        signals.session_revoked.send(
            sender=get_user_model(),
            request=self.request,
            user=record.native.user,
            scope=scope,
            session_id=session_id,
            revoked_count=event.revoked_count,
        )


class DjangoLogin:
    """Completes a verified provider sign-in with ``django.contrib.auth``."""

    def __init__(self, request: HttpRequest, bridge: _Signals) -> None:
        self.request = request
        self.bridge = bridge
        session = request.session
        if not isinstance(session, DatabaseSessionStore):
            raise ImproperlyConfigured(
                "Cross Auth's Django views need database-backed sessions "
                "(SESSION_ENGINE db, cached_db or cross_auth.django.sessions)"
            )
        self.session = session
        self.alias = (
            session.alias
            if isinstance(session, SessionStore)
            else router.db_for_write(session.get_model_class())
        )

    def on_commit(self, callback: CommitCallback) -> None:
        transaction.on_commit(callback, using=self.alias, robust=False)

    def login(
        self, user: User, *, response: CrossWebResponse, login_method: str
    ) -> CrossWebResponse:
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
            # cross_auth.django.sessions records it as the session's login
            # method while the session stays logged in with BACKEND.
            self.session[LOGIN_METHOD_SESSION_KEY] = event.login_method
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
                login_method=login_method,
            ),
            hooks=self.bridge.login_hooks(user),
            issue=issue,
            on_commit=self.on_commit,
            # Django's own rule, the backend's user_can_authenticate, is
            # checked above, and by the context before the callback gets here.
            check_user=None,
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


class _Bridge(Protocol):
    """Whatever sends a view's signals from core's hooks."""

    hooks: HookRegistry


def _may_sign_in(user: User) -> bool:
    """Refuse a user Django's backend refuses, with the login's own error.

    The cookie login checks the same rule itself. A sign-in for a bearer
    token never gets there, so the context checks it for both: before an
    authorization code is issued, and again before its token is.
    """
    if not _can_authenticate(user):
        raise CrossAuthException("access_denied", _INACTIVE, status_code=403)
    return True


def _context(request: HttpRequest, bridge: _Bridge) -> Context:
    """Build the core context, whose hooks send ``bridge``'s signals."""
    conf = get_settings()
    accounts = DjangoAccountsStorage()
    secondary = DjangoSecondaryStorage()
    aliases = {accounts.alias, secondary.alias}
    config: Config = {
        "account_linking": conf.account_linking,
        "require_verified_email": conf.require_verified_email,
    }
    sessions = None
    oauth_server = None
    if conf.oauth_server is not None:
        sessions = DjangoSessionStorage()
        aliases.add(sessions.alias)
        config["session"] = _session_config(conf)
        oauth_server = OAuthServer(get_client=conf.oauth_server.get_client)
    for alias in aliases:
        if connections[alias].in_atomic_block:
            raise ImproperlyConfigured(
                "Cross Auth's Django views must not run inside transaction.atomic"
            )
    return Context(
        secondary_storage=secondary,
        accounts_storage=accounts,
        session_storage=sessions,
        get_user_from_request=lambda _: _current_user(request),
        base_url=conf.base_url,
        config=config,
        default_next_url=_default_next_url(),
        hooks=bridge.hooks,
        oauth_server=oauth_server,
        user_can_authenticate=_may_sign_in,
    )


def _require_oauth_server() -> None:
    if get_settings().oauth_server is None:
        raise Http404("The OAuth server is not enabled")


class _ClientRequestAdapter(DjangoHTTPRequestAdapter):
    """The request of an OAuth client's own code, not of a browser page.

    Its form is a plain dict, as core's token endpoint reads it. It has no
    cookies: the client authenticates with what it sends in the body or the
    ``Authorization`` header, so a browser's cookies must change nothing on
    views that skip CSRF checks.
    """

    @property
    def post_data(self) -> dict[str, str]:
        return self.request.POST.dict()

    @property
    def cookies(self) -> dict[str, str]:
        return {}


def _to_json(response: CrossWebResponse) -> HttpResponse:
    """Send core's response as it is: JSON errors stay JSON, and no cookie is set."""
    result = HttpResponse(response.body or b"", status=response.status_code)
    if not response.body:
        # Django names a content type even when there is no content.
        del result["Content-Type"]
    for name, value in (response.headers or {}).items():
        result[name] = value
    return result


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
def authorize(request: HttpRequest, provider: str) -> HttpResponse:
    """Start a sign-in with ``provider`` for one of your OAuth clients.

    The client sends the user's browser here with ``client_id``,
    ``redirect_uri``, ``response_type=code``, a PKCE ``code_challenge`` with
    ``code_challenge_method=S256`` and, optionally, ``state`` and
    ``login_hint``. The sign-in ends at ``redirect_uri`` with a one-time
    ``code`` for the token view, or with an ``error``.
    """
    _require_oauth_server()
    oauth_provider = _provider(provider)
    bridge = _Signals(request, oauth_provider)
    response = start_token_flow(
        oauth_provider, HTTPRequest.from_django(request), _context(request, bridge)
    )
    return _to_django(request, response)


@csrf_exempt
@_auth_view("POST")
def token(request: HttpRequest) -> HttpResponse:
    """Exchange the code a sign-in ended with for a bearer token.

    The client posts a form with ``grant_type=authorization_code``, ``code``,
    ``client_id``, ``redirect_uri`` and the PKCE ``code_verifier``.
    """
    _require_oauth_server()
    response = Issuer().token(
        HTTPRequest(_ClientRequestAdapter(request)),
        _context(request, _TokenSignals(request)),
    )
    return _to_json(response)


@csrf_exempt
@_auth_view("POST")
def logout(request: HttpRequest) -> HttpResponse:
    """Revoke the bearer token in the request's ``Authorization`` header.

    A JSON body of ``{"scope": "all"}`` revokes every session of the token's
    user: their bearer tokens and, with ``cross_auth.django.sessions`` as the
    session engine, their browser sessions. Answers 204, also without a token
    to revoke. It reads no cookie, so it never ends the session of the browser
    that sends the request: use Django's ``logout`` for that.
    """
    _require_oauth_server()
    response = revoke_bearer_session(
        HTTPRequest(_ClientRequestAdapter(request)),
        _context(request, _LogoutSignals(request)),
    )
    return _to_json(response)


@_auth_view("GET")
def callback(request: HttpRequest, provider: str) -> HttpResponse:
    """Finish a sign-in or link when the provider redirects back."""
    oauth_provider = _provider(provider)
    bridge = _Signals(request, oauth_provider)
    try:
        response = handle_callback(
            oauth_provider,
            HTTPRequest.from_django(request),
            _context(request, bridge),
            login=DjangoLogin(request, bridge),
            on_verified=bridge.verified,
        )
    except PermissionDenied as error:
        # From a receiver, or from the CREATE_USER factory.
        response = bridge.refusal(error)
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
