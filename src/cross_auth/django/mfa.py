"""Two-factor authentication for Django: TOTP authenticators and recovery codes.

Turn it on with ``CROSS_AUTH["MFA"]``, Cross Auth's session engine and this
module's middleware::

    CROSS_AUTH = {..., "MFA": {"issuer": "Acme"}}
    SESSION_ENGINE = "cross_auth.django.sessions"
    MIDDLEWARE = [
        ...,
        "cross_auth.django.sessions.SessionMiddleware",
        ...,
        "django.contrib.auth.middleware.AuthenticationMiddleware",
        "cross_auth.django.mfa.MFAMiddleware",
        ...,
    ]

Every rule (which sign-ins need a code, checking codes, lockouts, recovery
codes, enrollment) is core's, shared with FastAPI; this module adapts it to
Django's requests and sessions.

Provider sign-ins are challenged by core before Django's ``login()`` runs.
Every other login (``LoginView``, the admin, ``PasswordResetConfirmView``,
any ``login()`` call) is caught by a ``user_logged_in`` receiver: it takes
the user back out of the session before the session is saved, and
``MFAMiddleware`` replaces that request's response with a redirect to the
``cross_auth:mfa_verify`` page (or a 401 JSON ``mfa_required`` for requests
that are not page navigations). The verify page restores the login once the
code checks out, without calling ``login()`` again, and sends
``mfa_verified``. For a user with 2FA, ``user_logged_in`` therefore means
the first factor passed; ``mfa_verified`` means a full sign-in.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from functools import wraps
from inspect import iscoroutinefunction
from typing import Any, TypeVar, cast
from urllib.parse import urlencode
from weakref import WeakKeyDictionary

from asgiref.sync import sync_to_async
from cross_web import HTTPRequest
from cross_web.request._django import DjangoHTTPRequestAdapter
from django.conf import settings
from django.contrib.auth import (
    BACKEND_SESSION_KEY,
    HASH_SESSION_KEY,
    REDIRECT_FIELD_NAME,
    SESSION_KEY,
    get_user_model,
    load_backend,
)
from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.decorators import login_not_required
from django.contrib.auth.models import AnonymousUser, update_last_login
from django.contrib.auth.views import redirect_to_login
from django.db import transaction
from django.http import (
    Http404,
    HttpRequest,
    HttpResponse,
    HttpResponseRedirect,
    JsonResponse,
)
from django.middleware.csrf import rotate_token
from django.shortcuts import render, resolve_url
from django.urls import reverse
from django.utils.cache import add_never_cache_headers
from django.utils.crypto import constant_time_compare
from django.utils.deprecation import MiddlewareMixin
from django.utils.http import url_has_allowed_host_and_scheme

from cross_auth import _mfa_flow as flow
from cross_auth._context import Context
from cross_auth._mfa import MFA, MFAStatus, TotpConfirmation, TotpEnrollment
from cross_auth._mfa_flow import MFASession
from cross_auth.exceptions import CrossAuthException, MFARequired
from cross_auth.hooks import AfterLoginEvent, BeforeLoginEvent, HookRegistry
from cross_auth.utils._response import Response as FlowResponse

from . import signals
from .conf import get_settings
from .models import Session
from .sessions import MFA_METHOD_SESSION_KEY, SessionStore
from .sessions import revoke_other_sessions as _revoke_other_sessions
from .storage import DjangoUser
from .views import (
    DjangoLogin,
    _auth_view,
    _context,
    _current_user,
    _default_next_url,
    _to_django,
    _to_json,
    mfa_checked,
    mfa_verify_url,
)

__all__ = [
    "MFAMiddleware",
    "PendingMFA",
    "confirm_totp_enrollment",
    "get_mfa_status",
    "get_pending_mfa",
    "mfa_required",
    "reauthenticate",
    "reauthentication_required",
    "regenerate_recovery_codes",
    "remove_mfa_factor",
    "start_totp_enrollment",
]

_ViewT = TypeVar("_ViewT", bound=Callable[..., Any])


class _Hooks:
    def __init__(self) -> None:
        self.hooks = HookRegistry()


class _LoginSignals(_Hooks):
    """Sends the login signals around the verify view's provider login."""

    def __init__(self, request: HttpRequest) -> None:
        super().__init__()
        self.request = request

    def login_hooks(self, user: DjangoUser) -> HookRegistry:
        sender = get_user_model()

        def before(event: BeforeLoginEvent) -> None:
            signals.before_login.send(
                sender=sender,
                request=self.request,
                provider=event.login_method,
                user_id=event.user_id,
                email=user.email,
            )

        def after(event: AfterLoginEvent) -> None:
            signals.after_login.send(
                sender=sender,
                request=self.request,
                provider=event.login_method,
                user=user.native,
            )

        hooks = HookRegistry()
        hooks.register_before("login", before)
        hooks.register_after("login", after)
        return hooks


def _mfa_context(request: HttpRequest, bridge: _Hooks | None = None) -> Context:
    """The core context, which must have 2FA on."""
    if get_settings().mfa is None:
        raise Http404("Two-factor authentication is not enabled")
    return _context(request, bridge or _Hooks(), check_atomic=False)


def _mfa(context: Context) -> MFA:
    assert context.mfa is not None
    return context.mfa


def _revoke_challenges(request: HttpRequest, user_id: str) -> None:
    """End the user's logins that are waiting for their second factor.

    ``revoke_other_sessions`` calls it, as core's revocations do: such a
    login holds no session to revoke yet. Without 2FA there are none.
    """
    if get_settings().mfa is None:
        return
    _mfa(_mfa_context(request)).revoke_challenges(user_id)


# The login guard -------------------------------------------------------------


@dataclass
class _Pending:
    """A login the guard took back, waiting for MFAMiddleware."""

    challenge: str | None
    methods: list[str] = field(default_factory=list)
    cookie_name: str = "mfa_challenge"
    cookie_max_age: int = 300
    # Set instead of a challenge when the login is refused outright, such as
    # mfa_enrollment_required.
    error: CrossAuthException | None = None


_pending: WeakKeyDictionary[HttpRequest, _Pending] = WeakKeyDictionary()


def _guard(
    sender: object,
    request: HttpRequest | None = None,
    user: AbstractBaseUser | None = None,
    **kwargs: Any,
) -> None:
    """``user_logged_in`` receiver: hold back a login that needs a second factor.

    ``login()`` has already given the session a new key and written the
    user into it. Taking the user back out before ``SessionMiddleware``
    saves the session means the database never holds a logged-in session
    for them; the challenge keeps what the verify page needs to restore it.
    """
    if request is None or user is None:
        return
    session = request.session
    # Every login starts without a second factor: only a completed challenge,
    # or Cross Auth's own login just after this, sets the marker again.
    session.pop(MFA_METHOD_SESSION_KEY, None)
    if get_settings().mfa is None or mfa_checked.get():
        return
    mfa = _mfa(_mfa_context(request))
    try:
        mfa.check_sign_in(str(user.pk), None)
        return
    except MFARequired as required:
        started = mfa.start_challenge(
            required,
            kind="framework",
            data={
                "backend": session.get(BACKEND_SESSION_KEY),
                "hash": session.get(HASH_SESSION_KEY),
            },
        )
        pending = _Pending(
            challenge=started.challenge,
            methods=started.methods,
            cookie_name=mfa.challenge_cookie,
            cookie_max_age=mfa.challenge_ttl,
        )
    except CrossAuthException as error:
        pending = _Pending(challenge=None, error=error)

    for key in (SESSION_KEY, BACKEND_SESSION_KEY, HASH_SESSION_KEY):
        session.pop(key, None)
    request.user = AnonymousUser()
    _pending[request] = pending


def _update_last_login(
    sender: object,
    request: HttpRequest | None = None,
    user: AbstractBaseUser | None = None,
    **kwargs: Any,
) -> None:
    """Django's ``update_last_login``, skipped for a login the guard held back.

    The verify page updates ``last_login`` once the login is complete, so it
    always means a full sign-in.
    """
    if user is None or (request is not None and request in _pending):
        return
    update_last_login(type(user), user)


def _safe_url(request: HttpRequest, url: str | None) -> str | None:
    if url and url_has_allowed_host_and_scheme(
        url, allowed_hosts={request.get_host()}, require_https=request.is_secure()
    ):
        return url
    return None


def _wants_json(request: HttpRequest) -> bool:
    return "json" in (request.content_type or "") or "application/json" in (
        request.headers.get("Accept") or ""
    )


def _secure(request: HttpRequest) -> bool:
    base_url = get_settings().base_url
    return request.is_secure() or bool(base_url and base_url.startswith("https://"))


class MFAMiddleware(MiddlewareMixin):
    """Replaces the response of a login that the guard held back.

    Page navigations (a redirect, or a form POST) go to the verify page,
    keeping the view's own redirect target as ``next``; anything else gets
    ``401 {"error": "mfa_required", "methods": [...], "verify_url": ...}``.
    Put it after ``AuthenticationMiddleware`` and inside the session
    middleware (system check ``cross_auth.E006``).
    """

    def process_response(
        self, request: HttpRequest, response: HttpResponse
    ) -> HttpResponse:
        pending = _pending.pop(request, None)
        if pending is None:
            return response

        # Browsers go to the verify page; JSON clients post to the view.
        verify_url = mfa_verify_url(get_settings())
        location = (
            response.get("Location") if 300 <= response.status_code < 400 else None
        )
        navigating = location is not None or (
            request.method == "POST" and not _wants_json(request)
        )

        if pending.error is not None:
            if navigating:
                result: HttpResponse = HttpResponseRedirect(
                    f"{verify_url}?{urlencode({'error': pending.error.error})}"
                )
                result.status_code = 303
            else:
                result = JsonResponse(
                    {
                        "error": pending.error.error,
                        "error_description": pending.error.error_description,
                    },
                    status=pending.error.status_code,
                )
            add_never_cache_headers(result)
            return result

        if navigating:
            next_url = _safe_url(
                request,
                location
                or request.POST.get(REDIRECT_FIELD_NAME)
                or request.GET.get(REDIRECT_FIELD_NAME),
            )
            target = verify_url
            if next_url is not None:
                target += "?" + urlencode({"next": next_url})
            result = HttpResponseRedirect(target)
            result.status_code = 303
        else:
            result = JsonResponse(
                {
                    "error": "mfa_required",
                    "error_description": "Two-factor authentication is required",
                    "methods": pending.methods,
                    "verify_url": reverse("cross_auth:mfa_verify"),
                },
                status=401,
            )
        assert pending.challenge is not None
        result.set_cookie(
            pending.cookie_name,
            pending.challenge,
            max_age=pending.cookie_max_age,
            path="/",
            secure=_secure(request),
            httponly=True,
            samesite="Lax",
        )
        add_never_cache_headers(result)
        return result


# Sessions --------------------------------------------------------------------


class DjangoMFASessions:
    """Core's ``MFASessions`` on ``cross_auth.django.sessions``.

    A session is named by its ``public_id``, which stays the same while its
    key changes, and signed in at its row's ``created_at``, which each login
    resets.
    """

    def __init__(self, request: HttpRequest) -> None:
        self.request = request

    def current(self, request: HTTPRequest, context: Context) -> MFASession | None:
        user = _current_user(self.request)
        store = self.request.session
        if user is None or not isinstance(store, SessionStore):
            return None
        if store.session_key is None:
            return None
        row = (
            Session.objects.using(store.alias)
            .filter(
                session_key=store.session_key,
                token_hash__isnull=True,
                revoked_at__isnull=True,
            )
            .only("public_id", "created_at", "login_method")
            .first()
        )
        if row is None:
            return None
        return MFASession(
            user=user,
            session_id=str(row.public_id),
            signed_in_at=row.created_at,
            login_method=row.login_method,
        )

    def revoke_others(
        self, request: HTTPRequest, context: Context, current: MFASession
    ) -> None:
        _revoke_other_sessions(self.request)


class _FormRequestAdapter(DjangoHTTPRequestAdapter):
    """A browser request whose form core reads as a plain dict."""

    @property
    def post_data(self) -> dict[str, str]:
        return self.request.POST.dict()


def _http(request: HttpRequest) -> HTTPRequest:
    return HTTPRequest(_FormRequestAdapter(request))


def _current(request: HttpRequest) -> tuple[Context, MFASession]:
    context = _mfa_context(request)
    current = DjangoMFASessions(request).current(_http(request), context)
    if current is None:
        raise CrossAuthException("unauthorized", "Not logged in", status_code=401)
    return context, current


# Functions for the application's own settings pages --------------------------


def get_mfa_status(request: HttpRequest) -> MFAStatus:
    """The signed-in user's factors and how many recovery codes are left."""
    context, current = _current(request)
    return flow.get_status(context, current)


def reauthenticate(
    request: HttpRequest,
    *,
    password: str | None = None,
    code: str | None = None,
    recovery_code: str | None = None,
) -> datetime:
    """Check one proof of identity; return until when 2FA changes are allowed.

    The password is checked with Django's ``check_password()``.
    """
    context, current = _current(request)
    return flow.reauthenticate(
        context, current, password=password, code=code, recovery_code=recovery_code
    )


def start_totp_enrollment(
    request: HttpRequest, *, name: str | None = None
) -> TotpEnrollment:
    """A new authenticator secret, waiting for its first code.

    Render ``otpauth_uri`` as a QR code yourself, on the server or in the
    browser; never send it to a QR service.
    """
    context, current = _current(request)
    return flow.start_totp_enrollment(context, current, name=name)


def confirm_totp_enrollment(
    request: HttpRequest,
    *,
    enrollment_id: str,
    code: str,
    revoke_other_sessions: bool = True,
) -> TotpConfirmation:
    """Store the authenticator once its first code checks out.

    The first factor also returns new recovery codes, shown once, and by
    default signs the user out of their other sessions.
    """
    context, current = _current(request)
    return flow.confirm_totp_enrollment(
        _http(request),
        context,
        DjangoMFASessions(request),
        current,
        enrollment_id=enrollment_id,
        code=code,
        revoke_other_sessions=revoke_other_sessions,
    )


def regenerate_recovery_codes(request: HttpRequest) -> list[str]:
    """Replace the user's recovery codes; return the new ones, shown once."""
    context, current = _current(request)
    return flow.regenerate_recovery_codes(context, current)


def remove_mfa_factor(request: HttpRequest, factor_id: str) -> MFAStatus:
    """Remove one factor; the last one turns 2FA off and deletes the codes."""
    context, current = _current(request)
    return flow.remove_mfa_factor(context, current, factor_id)


# Decorators ------------------------------------------------------------------


def _decorate(
    view: _ViewT, check: Callable[[HttpRequest], HttpResponse | None]
) -> _ViewT:
    if iscoroutinefunction(view):

        @wraps(view)
        async def async_wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> Any:
            refused = await sync_to_async(check)(request)
            if refused is not None:
                return refused
            return await view(request, *args, **kwargs)

        return cast(_ViewT, async_wrapper)

    @wraps(view)
    def wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> Any:
        refused = check(request)
        if refused is not None:
            return refused
        return view(request, *args, **kwargs)

    return cast(_ViewT, wrapper)


def mfa_required(
    view: _ViewT | None = None,
    *,
    login_url: str | None = None,
    redirect_field_name: str = REDIRECT_FIELD_NAME,
) -> Any:
    """Like ``login_required``, but the session's sign-in must have passed 2FA.

    A user who signed in without a second factor, such as one who has none,
    is sent to the login page.
    """

    def check(request: HttpRequest) -> HttpResponse | None:
        if request.user.is_authenticated and request.session.get(
            MFA_METHOD_SESSION_KEY
        ):
            return None
        return redirect_to_login(
            request.get_full_path(), login_url, redirect_field_name
        )

    def decorate(view: _ViewT) -> _ViewT:
        return _decorate(view, check)

    return decorate if view is None else decorate(view)


def reauthentication_required(
    url: str, *, redirect_field_name: str = REDIRECT_FIELD_NAME
) -> Callable[[_ViewT], _ViewT]:
    """Send a session that has not proved who it is recently to ``url``.

    "Recently" is ``CROSS_AUTH["MFA"]["reauthentication_max_age"]`` (five
    minutes by default) since the sign-in or the last ``reauthenticate``:
    the same rule that enrolling, regenerating codes and removing factors
    enforce. A device login's sign-in does not count. ``url`` is your confirm-identity page; it gets the current path
    as ``next``. Users who are not signed in go to the login page.
    """

    def check(request: HttpRequest) -> HttpResponse | None:
        try:
            context, current = _current(request)
        except CrossAuthException:
            return redirect_to_login(request.get_full_path())
        mfa = _mfa(context)
        max_age = timedelta(seconds=mfa.config["reauthentication_max_age"])
        authenticated = flow.authenticated_at(context, current)
        if (
            authenticated is not None
            and datetime.now(tz=timezone.utc) - authenticated <= max_age
        ):
            return None
        return redirect_to_login(request.get_full_path(), url, redirect_field_name)

    def decorate(view: _ViewT) -> _ViewT:
        return _decorate(view, check)

    return decorate


# Views -----------------------------------------------------------------------


def _json_view(
    handler: Callable[[HTTPRequest, Context, flow.MFASessions], FlowResponse],
    method: str,
) -> Callable[..., HttpResponse]:
    """A JSON view over one of core's shared 2FA route handlers."""

    @_auth_view(method)
    def view(request: HttpRequest, **kwargs: Any) -> HttpResponse:
        context = _mfa_context(request)
        return _to_json(handler(_http(request), context, DjangoMFASessions(request)))

    view.__doc__ = handler.__doc__
    return view


status = _json_view(flow.status_handler, "GET")
enroll = _json_view(flow.enroll_handler, "POST")
confirm = _json_view(flow.confirm_handler, "POST")
recovery_codes = _json_view(flow.recovery_codes_handler, "POST")
remove = _json_view(flow.remove_handler, "POST")
# Allowed under LoginRequiredMiddleware like the verify view, so that
# reauthentication_required's page can post here; it still answers 401
# without a session.
reauthenticate_view = login_not_required(
    _json_view(flow.reauthenticate_handler, "POST")
)


@dataclass(frozen=True)
class PendingMFA:
    """A sign-in waiting for its second factor, for the app's verify page."""

    # How it can finish: "totp", and "recovery_code" while codes are left.
    methods: list[str]


def get_pending_mfa(request: HttpRequest) -> PendingMFA | None:
    """The sign-in this browser is finishing, or None when it has expired.

    For an application's own verify page (``CROSS_AUTH["MFA"]["verify_url"]``):
    render a form for each method that posts ``code`` or ``recovery_code``,
    and ``next``, to ``cross_auth:mfa_verify``. A wrong code comes back to
    the page with ``?error=`` and ``next``.
    """
    mfa = _mfa(_mfa_context(request))
    token = request.COOKIES.get(mfa.challenge_cookie)
    challenge = mfa.load_challenge(token) if token else None
    if challenge is None:
        return None
    state = mfa.status(challenge.user_id)
    methods = sorted({factor.type for factor in state.factors})
    if state.recovery_codes_remaining:
        methods.append("recovery_code")
    return PendingMFA(methods=methods)


def _custom_verify_url() -> str | None:
    mfa = get_settings().mfa
    if mfa is None or mfa.verify_url is None:
        return None
    return resolve_url(mfa.verify_url)


def _verify_page(
    request: HttpRequest, *, error: str | None, status: int = 200
) -> HttpResponse:
    pending = get_pending_mfa(request)
    if pending is None and error is None:
        error = "invalid_challenge"
    next_url = _safe_url(request, request.POST.get("next") or request.GET.get("next"))
    return render(
        request,
        "cross_auth/mfa_verify.html",
        {
            "error": error,
            "expired": pending is None,
            "methods": pending.methods if pending is not None else [],
            "next": next_url or "",
            "login_url": resolve_url(settings.LOGIN_URL),
        },
        status=status,
    )


def _restore(request: HttpRequest, finished: flow.Finished) -> AbstractBaseUser:
    """Log in again the user a guarded login held back."""
    assert finished.challenge is not None and finished.user is not None
    data = finished.challenge.data
    backend_path = data.get("backend")
    stored_hash = data.get("hash")
    native = None
    if (
        isinstance(backend_path, str)
        and backend_path in settings.AUTHENTICATION_BACKENDS
    ):
        # Asked the way Django restores request.user: an inactive user, or
        # one the backend no longer knows, does not come back.
        native = load_backend(backend_path).get_user(finished.user.id)
    if (
        native is None
        or not isinstance(stored_hash, str)
        or not constant_time_compare(stored_hash, native.get_session_auth_hash())
    ):
        # Their password changed meanwhile, or they may no longer sign in.
        raise CrossAuthException(
            "invalid_challenge", "This sign-in has expired; sign in again"
        )
    session = request.session
    session.cycle_key()
    session[SESSION_KEY] = native._meta.pk.value_to_string(native)
    session[BACKEND_SESSION_KEY] = backend_path
    session[HASH_SESSION_KEY] = native.get_session_auth_hash()
    assert finished.mfa_method is not None
    session[MFA_METHOD_SESSION_KEY] = finished.mfa_method
    if isinstance(session, SessionStore):
        # A new sign-in: new public_id and created_at at the next save.
        session._logged_in()
    request.user = native
    rotate_token(request)
    if hasattr(native, "last_login"):
        update_last_login(type(native), native)
    return native


@_auth_view("GET")
def _verify_get(request: HttpRequest) -> HttpResponse:
    page = _custom_verify_url()
    if page is not None:
        # The application draws the page; keep next and error.
        query = request.META.get("QUERY_STRING", "")
        return HttpResponseRedirect(f"{page}?{query}" if query else page)
    return _verify_page(request, error=request.GET.get("error"))


@_auth_view("POST")
def _verify_post(request: HttpRequest) -> HttpResponse:
    bridge = _LoginSignals(request)
    context = _mfa_context(request, bridge)
    mfa = _mfa(context)
    http = _http(request)
    try:
        fields = flow.read_fields(http)
        token = fields.get("challenge") or request.COOKIES.get(mfa.challenge_cookie)
        if not isinstance(token, str) or not token:
            raise CrossAuthException(
                "invalid_challenge", "This sign-in has expired; sign in again"
            )
        code = fields.get("code") or None
        recovery_code = fields.get("recovery_code") or None
        finished = flow.finish_challenge(
            http,
            context,
            token,
            code=code if isinstance(code, str) else None,
            recovery_code=recovery_code if isinstance(recovery_code, str) else None,
            login=DjangoLogin(request, bridge, mfa=mfa),
        )
        assert finished.challenge is not None
        user: AbstractBaseUser | None = None
        if finished.challenge.kind == "framework":
            user = _restore(request, finished)
            next_url = (
                _safe_url(request, request.POST.get("next")) or _default_next_url()
            )
            if _wants_json(request):
                response: HttpResponse = JsonResponse({"redirect_to": next_url})
            else:
                response = HttpResponseRedirect(next_url)
                response.status_code = 303
            response.delete_cookie(mfa.challenge_cookie, path="/", samesite="Lax")
        else:
            if isinstance(finished.user, DjangoUser):
                user = finished.user.native
            response = _to_django(request, finished.response)
    except CrossAuthException as error:
        if _wants_json(request):
            return _to_json(flow.error_response(error))
        page = _custom_verify_url()
        if page is not None:
            query = {"error": error.error}
            next_url = _safe_url(request, request.POST.get("next"))
            if next_url is not None:
                query["next"] = next_url
            back = HttpResponseRedirect(f"{page}?{urlencode(query)}")
            back.status_code = 303
            return back
        return _verify_page(request, error=error.error, status=error.status_code)
    if user is not None:
        signals.mfa_verified.send(
            sender=get_user_model(),
            request=request,
            user=user,
            method=finished.mfa_method,
        )
    return response


@login_not_required
def verify(request: HttpRequest) -> HttpResponse:
    """GET: the code form. POST ``code`` or ``recovery_code``: finish the sign-in.

    Every sign-in waiting for its second factor comes here: Django's own
    logins held back by the guard, provider sign-ins and the OAuth server's
    sign-ins for your clients. The challenge travels in an HttpOnly cookie.
    JSON posts get JSON back: ``{"redirect_to": ...}`` or an error.
    """
    if request.method == "GET":
        return _verify_get(request)
    return _verify_post(request)


# Django reads ATOMIC_REQUESTS opt-outs off the URL's view, not the inner ones.
for _alias in settings.DATABASES:
    verify = transaction.non_atomic_requests(using=_alias)(verify)
