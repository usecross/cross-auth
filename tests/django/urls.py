from django.urls import include, path

from . import views

urlpatterns = [
    path("auth/", include("cross_auth.django.urls")),
    path("accounts/", include("django.contrib.auth.urls")),
    path("private/", views.private, name="private"),
    path("remember/", views.remember),
    path("sessions/", views.sessions),
    path("", views.home, name="home"),
]
