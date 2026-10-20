"""Run examples/django through manage.py and runserver, without Google."""

import os
import shutil
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

EXAMPLE = Path(__file__).parents[2] / "examples" / "django"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture(scope="module")
def project(tmp_path_factory: pytest.TempPathFactory) -> Path:
    path = tmp_path_factory.mktemp("example") / "django"
    shutil.copytree(EXAMPLE, path, ignore=shutil.ignore_patterns("db.sqlite3", ".env"))
    return path


@pytest.fixture(scope="module")
def env() -> dict[str, str]:
    return {
        **{
            key: value
            for key, value in os.environ.items()
            if not key.startswith(("DJANGO_", "CROSS_AUTH_"))
        },
        "GOOGLE_CLIENT_ID": "fake-client-id.apps.googleusercontent.com",
        "GOOGLE_CLIENT_SECRET": "fake-client-secret",
    }


def manage(project: Path, env: dict[str, str], *args: str) -> str:
    result = subprocess.run(
        [sys.executable, "manage.py", *args],
        cwd=project,
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout + result.stderr


@pytest.fixture(scope="module")
def server(project: Path, env: dict[str, str]) -> Iterator[str]:
    manage(project, env, "migrate", "--no-input")
    port = _free_port()
    process = subprocess.Popen(
        [sys.executable, "manage.py", "runserver", f"127.0.0.1:{port}", "--noreload"],
        cwd=project,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(100):
            try:
                httpx.get(base)
                break
            except httpx.TransportError:
                time.sleep(0.1)
        yield base
    finally:
        process.terminate()
        process.wait(timeout=10)


def test_check_and_migrations(project: Path, env: dict[str, str]) -> None:
    assert "no issues" in manage(project, env, "check")
    manage(project, env, "makemigrations", "--check", "--dry-run")


def test_ready_connects_the_signal_receivers(
    project: Path, env: dict[str, str]
) -> None:
    code = (
        # Checked before this code imports core.signals itself.
        "from cross_auth.django.signals import before_callback, user_created; "
        "assert before_callback.has_listeners() and user_created.has_listeners(); "
        "from core import signals; "
        "assert signals.ALLOWED_EMAIL_DOMAIN is None"
    )
    manage(project, env, "shell", "-c", code)


def test_google_sign_in_starts_with_the_registered_redirect_uri(server: str) -> None:
    with httpx.Client(base_url=server) as browser:
        home = browser.get("/")
        assert home.status_code == 200
        assert 'action="/auth/google/login/"' in home.text

        refused = browser.post("/auth/google/login/")
        assert refused.status_code == 403

        response = browser.post(
            "/auth/google/login/",
            data={"csrfmiddlewaretoken": browser.cookies["csrftoken"]},
            headers={"Referer": f"{server}/"},
        )

    assert response.status_code == 302
    location = urlparse(response.headers["location"])
    assert location.netloc == "accounts.google.com"
    params = parse_qs(location.query)
    # The tutorial registers exactly this URI with Google.
    assert params["redirect_uri"] == [f"{server}/auth/google/callback"]
    assert params["scope"] == ["openid email profile"]
    assert params["client_id"] == ["fake-client-id.apps.googleusercontent.com"]
    cookies = {cookie.name for cookie in browser.cookies.jar}
    assert cookies - {"csrftoken"} == {f"cross_auth_oauth_{params['state'][0]}"}


def test_profile_requires_login(server: str) -> None:
    response = httpx.get(f"{server}/profile/")

    assert response.status_code == 302
    assert response.headers["location"] == "/accounts/login/?next=/profile/"
