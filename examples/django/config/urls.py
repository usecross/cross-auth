from django.contrib import admin
from django.urls import include, path

from core import views

urlpatterns = [
    path("admin/", admin.site.urls),
    path("accounts/", include("django.contrib.auth.urls")),
    path("auth/", include("cross_auth.django.urls")),
    path("profile/", views.profile, name="profile"),
    path("", views.home, name="home"),
]
