"""URLs for provider sign-in; include them under a prefix such as ``auth/``.

The provider sends users back to ``<prefix><provider>/callback`` (no trailing
slash), which is the redirect URI to register with the provider.
"""

from django.urls import path

from . import views

app_name = "cross_auth"

urlpatterns = [
    path("<str:provider>/login/", views.login, name="login"),
    path("<str:provider>/link/", views.link, name="link"),
    # Cross Auth derives the callback URL from the login and link URLs by
    # replacing their last segment, so it stays a sibling without a slash.
    path("<str:provider>/callback", views.callback, name="callback"),
    path(
        "<str:provider>/accounts/<int:social_account_id>/disconnect/",
        views.disconnect,
        name="disconnect",
    ),
]
