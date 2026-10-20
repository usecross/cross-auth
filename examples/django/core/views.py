from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render


def home(request: HttpRequest) -> HttpResponse:
    return render(request, "core/home.html")


@login_required
def profile(request: HttpRequest) -> HttpResponse:
    return render(request, "core/profile.html")
