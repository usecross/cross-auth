from django.contrib import admin
from django.urls import include, path

from core import views

urlpatterns = [
    path("admin/", admin.site.urls),
    # Before django.contrib.auth.urls, so its login URL renders our page.
    path("accounts/login/", views.LoginView.as_view(), name="login"),
    path("accounts/", include("django.contrib.auth.urls")),
    path("auth/", include("cross_auth.django.urls")),
    path("accounts/2fa/", views.two_factor_verify, name="two_factor_verify"),
    path("profile/", views.profile, name="profile"),
    path("settings/2fa/", views.two_factor, name="two_factor"),
    path("settings/2fa/start/", views.two_factor_start, name="two_factor_start"),
    path("settings/2fa/confirm/", views.two_factor_confirm, name="two_factor_confirm"),
    path(
        "settings/2fa/recovery-codes/",
        views.two_factor_recovery_codes,
        name="two_factor_recovery_codes",
    ),
    path(
        "settings/2fa/<str:factor_id>/remove/",
        views.two_factor_remove,
        name="two_factor_remove",
    ),
    path(
        "settings/confirm-identity/",
        views.confirm_identity,
        name="confirm_identity",
    ),
    path("", views.home, name="home"),
]
