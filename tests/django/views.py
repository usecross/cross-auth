from dataclasses import asdict

from django.contrib.auth import aauthenticate, alogin, authenticate, login
from django.http import HttpResponseRedirect
from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, HttpResponse, HttpResponseNotAllowed, JsonResponse
from django.middleware.csrf import get_token

from cross_auth.django.sessions import (
    list_sessions,
    revoke_other_sessions,
    revoke_session,
)
from cross_auth.django.mfa import (
    get_pending_mfa,
    mfa_required,
    reauthentication_required,
)
from cross_auth.django.tokens import authenticate_bearer


def home(request: HttpRequest) -> HttpResponse:
    get_token(request)
    user = request.user
    return JsonResponse(
        {
            "authenticated": user.is_authenticated,
            "user_id": str(user.pk) if user.is_authenticated else None,
            "backend": request.session.get("_auth_user_backend"),
        }
    )


@login_required
def private(request: HttpRequest) -> HttpResponse:
    return HttpResponse("private")


def remember(request: HttpRequest) -> HttpResponse:
    """Write to the session, as an anonymous cart would."""
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])
    request.session["remembered"] = request.POST.get("value", "yes")
    return HttpResponse("remembered")


def sessions(request: HttpRequest) -> HttpResponse:
    if request.method == "POST":
        if "id" in request.POST:
            return JsonResponse(
                {"revoked": revoke_session(request, request.POST["id"])}
            )
        return JsonResponse({"revoked": revoke_other_sessions(request)})
    return JsonResponse(
        {"sessions": [asdict(session) for session in list_sessions(request)]}
    )


def me(request: HttpRequest) -> HttpResponse:
    """An API view for the OAuth server's clients, as an application writes one."""
    authenticated = authenticate_bearer(request)
    if authenticated is None:
        return JsonResponse({"error": "invalid_token"}, status=401)
    return JsonResponse(
        {
            "user_id": str(authenticated.user.pk),
            "client_id": authenticated.session.client_id,
            "session_id": str(authenticated.session.id),
            "django_user": request.user.is_authenticated,
        }
    )


def api_login(request: HttpRequest) -> HttpResponse:
    """A JSON password login, as a single-page app's backend writes one."""
    user = authenticate(
        request,
        username=request.POST.get("username"),
        password=request.POST.get("password"),
    )
    if user is None:
        return JsonResponse({"error": "invalid_credentials"}, status=400)
    login(request, user)
    return JsonResponse({"user_id": str(user.pk)})


@mfa_required
def two_factor_only(request: HttpRequest) -> HttpResponse:
    return HttpResponse("verified")


@reauthentication_required("/confirm-identity/")
def recently_authenticated(request: HttpRequest) -> HttpResponse:
    """A settings page that needs a recent sign-in or reauthentication."""
    return HttpResponse("recent")


def own_verify_page(request: HttpRequest) -> HttpResponse:
    """An application's verify page (CROSS_AUTH["MFA"]["verify_url"])."""
    get_token(request)
    pending = get_pending_mfa(request)
    return JsonResponse(
        {
            "methods": None if pending is None else pending.methods,
            "error": request.GET.get("error"),
            "next": request.GET.get("next"),
        }
    )


async def async_login(request: HttpRequest) -> HttpResponse:
    """An async password login view."""
    user = await aauthenticate(
        request,
        username=request.POST.get("username"),
        password=request.POST.get("password"),
    )
    assert user is not None
    await alogin(request, user)
    return HttpResponseRedirect("/private/")
