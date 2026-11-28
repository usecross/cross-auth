"""URLs for provider sign-in; include them under a prefix such as ``auth/``.

The provider sends users back to ``<prefix><provider>/callback`` (no trailing
slash), which is the redirect URI to register with the provider.
"""

from django.urls import path

from . import mfa, views

app_name = "cross_auth"

urlpatterns = [
    path("<str:provider>/login/", views.login, name="login"),
    path("<str:provider>/link/", views.link, name="link"),
    # The OAuth server's views, for SPA and native clients. Like the callback,
    # they have no trailing slash: clients build these addresses themselves,
    # and a POST cannot be redirected to add one.
    path("<str:provider>/authorize", views.authorize, name="authorize"),
    path("token", views.token, name="token"),
    path("logout", views.logout, name="logout"),
    # Two-factor authentication, with CROSS_AUTH["MFA"]; otherwise they
    # answer "not found". The paths and JSON bodies are the FastAPI router's.
    path("mfa", mfa.status, name="mfa"),
    path("mfa/verify", mfa.verify, name="mfa_verify"),
    path("mfa/totp/enroll", mfa.enroll, name="mfa_enroll"),
    path("mfa/totp/confirm", mfa.confirm, name="mfa_confirm"),
    path("mfa/recovery-codes", mfa.recovery_codes, name="mfa_recovery_codes"),
    path("mfa/factors/<str:factor_id>/remove", mfa.remove, name="mfa_remove"),
    path("reauthenticate", mfa.reauthenticate_view, name="reauthenticate"),
    # Cross Auth derives the callback URL from the login and link URLs by
    # replacing their last segment, so it stays a sibling without a slash.
    path("<str:provider>/callback", views.callback, name="callback"),
    path(
        "<str:provider>/accounts/<int:social_account_id>/disconnect/",
        views.disconnect,
        name="disconnect",
    ),
]
