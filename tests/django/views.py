from dataclasses import asdict

from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, HttpResponse, HttpResponseNotAllowed, JsonResponse
from django.middleware.csrf import get_token

from cross_auth.django.sessions import (
    list_sessions,
    revoke_other_sessions,
    revoke_session,
)


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
