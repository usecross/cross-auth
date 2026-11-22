from collections.abc import Callable
from functools import wraps
from typing import Any, Concatenate, ParamSpec

import qrcode
import qrcode.image.svg
from cross_inertia.django import render
from django.contrib.auth import views as auth_views
from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, HttpResponse, HttpResponseNotAllowed
from django.shortcuts import redirect
from django.urls import reverse

from cross_auth.django.mfa import (
    confirm_totp_enrollment,
    get_mfa_status,
    get_pending_mfa,
    reauthenticate,
    regenerate_recovery_codes,
    remove_mfa_factor,
    start_totp_enrollment,
)
from cross_auth.django.models import SocialAccount
from cross_auth.exceptions import CrossAuthException

ERRORS = {
    "invalid_code": "That code is not correct.",
    "invalid_password": "That password is not correct.",
    "email_not_verified": (
        "Connect a Google account with your email address before turning on "
        "two-factor authentication."
    ),
    "enrollment_not_found": "That took too long. Start again.",
    "mfa_locked": "Too many wrong codes. Wait a few minutes.",
    "invalid_challenge": "This sign-in has expired.",
    "mfa_enrollment_required": (
        "This account must turn on two-factor authentication before it can sign in."
    ),
}

# The two-factor pages in ../frontend/src/pages/two-factor are shared with the
# FastAPI example; each backend passes its own URLs and picks its layout.
SITE = "django"

_P = ParamSpec("_P")


def post_only(
    view: Callable[Concatenate[HttpRequest, _P], HttpResponse],
) -> Callable[Concatenate[HttpRequest, _P], HttpResponse]:
    """Like Django's ``require_POST``: these views change the user's 2FA."""

    @wraps(view)
    def wrapper(
        request: HttpRequest, *args: _P.args, **kwargs: _P.kwargs
    ) -> HttpResponse:
        if request.method != "POST":
            return HttpResponseNotAllowed(["POST"])
        return view(request, *args, **kwargs)

    return wrapper


def home(request: HttpRequest) -> HttpResponse:
    return render(request, "django/Home")


@login_required
def profile(request: HttpRequest) -> HttpResponse:
    accounts = SocialAccount.objects.filter(user_id=request.user.pk)
    return render(
        request,
        "django/Profile",
        {
            "social_accounts": [
                {
                    "id": account.pk,
                    "provider": account.provider,
                    "provider_email": account.provider_email,
                    "disconnect_url": reverse(
                        "cross_auth:disconnect", args=[account.provider, account.pk]
                    ),
                }
                for account in accounts
            ],
            "two_factor_url": reverse("two_factor"),
        },
    )


class LoginView(auth_views.LoginView):
    """Django's LoginView, with its form rendered by the shared frontend."""

    def render_to_response(
        self, context: dict[str, Any], **response_kwargs: Any
    ) -> HttpResponse:
        form = context["form"]
        return render(
            self.request,
            "django/Login",
            {
                "next": context["next"],
                "username": form["username"].value() or "",
                # Field errors too: a whitespace-only username passes the
                # browser's required check but fails Django's.
                "form_errors": [
                    str(error) for errors in form.errors.values() for error in errors
                ],
            },
        )


def two_factor_verify(request: HttpRequest) -> HttpResponse:
    """The code step of every sign-in (CROSS_AUTH["MFA"]["verify_url"]).

    Its forms post to Cross Auth's verify view, which finishes the sign-in and
    sends wrong codes back here with ``?error=``.
    """
    pending = get_pending_mfa(request)
    error = request.GET.get("error")
    return render(
        request,
        "two-factor/Verify",
        {
            "site": SITE,
            "error": ERRORS.get(error or "", error),
            "expired": pending is None,
            "methods": [] if pending is None else pending.methods,
            "next": request.GET.get("next", ""),
            "urls": {
                "verify": reverse("cross_auth:mfa_verify"),
                "sign_in": reverse("login"),
            },
        },
    )


def _qr_svg(uri: str) -> str:
    # Rendered here, never by a QR service: the URI contains the secret.
    image = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage)
    return image.to_string(encoding="unicode")


def _settings_page(
    request: HttpRequest, *, error: str | None = None, status: int = 200
) -> HttpResponse:
    mfa = get_mfa_status(request)
    return render(
        request,
        "two-factor/Settings",
        {
            "site": SITE,
            "error": ERRORS.get(error or "", error),
            "mfa": {
                "enabled": mfa.enabled,
                "recovery_codes_remaining": mfa.recovery_codes_remaining,
                "factors": [
                    {
                        "id": factor.id,
                        "name": factor.name or "Authenticator app",
                        "added": f"{factor.created_at.day} {factor.created_at:%b %Y}",
                        "remove_url": reverse("two_factor_remove", args=[factor.id]),
                    }
                    for factor in mfa.factors
                ],
            },
            "urls": {
                "start": reverse("two_factor_start"),
                "recovery_codes": reverse("two_factor_recovery_codes"),
                "back": reverse("profile"),
            },
        },
        status_code=status,
    )


def _refused(request: HttpRequest, error: CrossAuthException) -> HttpResponse:
    # Changing 2FA needs a recent sign-in; send the user to confirm it is them.
    if error.error == "reauthentication_required":
        return redirect("confirm_identity")
    return _settings_page(request, error=error.error, status=error.status_code)


def _enroll_page(
    request: HttpRequest,
    *,
    enrollment_id: str,
    secret: str,
    otpauth_uri: str,
    error: str | None = None,
) -> HttpResponse:
    return render(
        request,
        "two-factor/Enroll",
        {
            "site": SITE,
            "enrollment_id": enrollment_id,
            "secret": secret,
            "otpauth_uri": otpauth_uri,
            "qr_svg": _qr_svg(otpauth_uri),
            "error": error,
            "urls": {
                "confirm": reverse("two_factor_confirm"),
                "cancel": reverse("two_factor"),
            },
        },
        status_code=400 if error else 200,
    )


def _codes_page(request: HttpRequest, codes: list[str]) -> HttpResponse:
    return render(
        request,
        "two-factor/RecoveryCodes",
        {"site": SITE, "codes": codes, "urls": {"done": reverse("two_factor")}},
    )


@login_required
def two_factor(request: HttpRequest) -> HttpResponse:
    return _settings_page(request)


@post_only
@login_required
def two_factor_start(request: HttpRequest) -> HttpResponse:
    try:
        enrollment = start_totp_enrollment(request, name="Authenticator app")
    except CrossAuthException as error:
        return _refused(request, error)
    return _enroll_page(
        request,
        enrollment_id=enrollment.enrollment_id,
        secret=enrollment.secret,
        otpauth_uri=enrollment.otpauth_uri,
    )


@post_only
@login_required
def two_factor_confirm(request: HttpRequest) -> HttpResponse:
    try:
        confirmed = confirm_totp_enrollment(
            request,
            enrollment_id=request.POST.get("enrollment_id", ""),
            code=request.POST.get("code", ""),
        )
    except CrossAuthException as error:
        if error.error != "invalid_code":
            return _refused(request, error)
        # Show the same secret again; the enrollment waits ten minutes.
        return _enroll_page(
            request,
            enrollment_id=request.POST.get("enrollment_id", ""),
            secret=request.POST.get("secret", ""),
            otpauth_uri=request.POST.get("otpauth_uri", ""),
            error=ERRORS["invalid_code"],
        )
    if confirmed.recovery_codes is None:
        return redirect("two_factor")
    return _codes_page(request, confirmed.recovery_codes)


@post_only
@login_required
def two_factor_recovery_codes(request: HttpRequest) -> HttpResponse:
    try:
        codes = regenerate_recovery_codes(request)
    except CrossAuthException as error:
        return _refused(request, error)
    return _codes_page(request, codes)


@post_only
@login_required
def two_factor_remove(request: HttpRequest, factor_id: str) -> HttpResponse:
    try:
        remove_mfa_factor(request, factor_id)
    except CrossAuthException as error:
        return _refused(request, error)
    return redirect("two_factor")


@login_required
def confirm_identity(request: HttpRequest) -> HttpResponse:
    error = None
    if request.method == "POST":
        try:
            reauthenticate(
                request,
                password=request.POST.get("password") or None,
                code=request.POST.get("code") or None,
            )
        except CrossAuthException as exc:
            error = ERRORS.get(exc.error, exc.error_description)
        else:
            return redirect("two_factor")
    return render(
        request,
        "two-factor/ConfirmIdentity",
        {
            "site": SITE,
            "error": error,
            "has_password": isinstance(request.user, AbstractBaseUser)
            and request.user.has_usable_password(),
            "urls": {
                "submit": reverse("confirm_identity"),
                "cancel": reverse("two_factor"),
            },
        },
        status_code=400 if error else 200,
    )
