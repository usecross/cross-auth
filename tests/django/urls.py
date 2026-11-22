from django.urls import include, path

from . import views

urlpatterns = [
    path("auth/", include("cross_auth.django.urls")),
    path("accounts/", include("django.contrib.auth.urls")),
    path("private/", views.private, name="private"),
    path("remember/", views.remember),
    path("sessions/", views.sessions),
    path("api/me", views.me),
    path("api/login", views.api_login),
    path("async-login", views.async_login),
    path("verified/", views.two_factor_only),
    path("sign-in/code/", views.own_verify_page, name="own_verify"),
    path("", views.home, name="home"),
]
