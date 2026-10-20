from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.middleware.csrf import get_token


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
