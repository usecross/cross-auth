from django.contrib import admin
from django.urls import include, path

from core import views

urlpatterns = [
    path("admin/", admin.site.urls),
    # Before django.contrib.auth.urls, so its login URL renders our page.
    path("accounts/login/", views.LoginView.as_view(), name="login"),
    path("accounts/", include("django.contrib.auth.urls")),
    path("auth/", include("cross_auth.django.urls")),
    path("profile/", views.profile, name="profile"),
    path("", views.home, name="home"),
]
