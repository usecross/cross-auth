from typing import Any

from cross_inertia.django import render
from django.contrib.auth import views as auth_views
from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, HttpResponse
from django.urls import reverse

from cross_auth.django.models import SocialAccount


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
            ]
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
