"""Router-level tests for the session (cookie) flow: /{provider}/login."""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import respx
from fastapi import FastAPI
from fastapi.testclient import TestClient

from cross_auth._session import get_session
from cross_auth._storage import SecondaryStorage

from .conftest import (
    load_auth_request,
    mock_token_and_userinfo,
    start_provider_auth,
)


def test_login_redirects_to_provider_with_state(
    client: TestClient, secondary_storage: SecondaryStorage
):
    _, state = start_provider_auth(client, "/fake/login")

    auth_req = load_auth_request(secondary_storage, state)
    assert auth_req.flow == "session"
    assert auth_req.provider_id == "fake"
    assert auth_req.next_url == "/"
    assert auth_req.provider_code_verifier is not None


def test_login_redirect_points_at_provider(client: TestClient):
    resp, _ = start_provider_auth(client, "/fake/login")
    location = resp.headers["location"]
    assert location.startswith("https://fake.example/oauth/authorize")
    qs = parse_qs(urlparse(location).query)
    assert qs["client_id"] == ["fake-client-id"]
    assert qs["response_type"] == ["code"]
    assert qs["code_challenge_method"] == ["S256"]


def test_login_stores_next_param_when_safe(
    client: TestClient, secondary_storage: SecondaryStorage
):
    _, state = start_provider_auth(client, "/fake/login", params={"next": "/dashboard"})
    assert load_auth_request(secondary_storage, state).next_url == "/dashboard"


def test_login_rejects_unsafe_next(
    client: TestClient, secondary_storage: SecondaryStorage
):
    for unsafe in ["https://evil.example/path", "//evil.example", "evil.com"]:
        _, state = start_provider_auth(client, "/fake/login", params={"next": unsafe})
        assert load_auth_request(secondary_storage, state).next_url == "/"


def test_login_respects_custom_default_next_url(
    build_auth, secondary_storage: SecondaryStorage
):
    auth = build_auth(default_next_url="/app")
    app = FastAPI()
    app.include_router(auth.router)
    with TestClient(app, follow_redirects=False) as c:
        _, state = start_provider_auth(c, "/fake/login")
    assert load_auth_request(secondary_storage, state).next_url == "/app"


@respx.mock
def test_session_callback_creates_session_and_redirects_to_next(
    client: TestClient, secondary_storage: SecondaryStorage
):
    mock_token_and_userinfo(email="alice@example.com")

    _, state = start_provider_auth(client, "/fake/login", params={"next": "/dashboard"})

    resp = client.get(
        "/fake/callback", params={"code": "provider-code", "state": state}
    )
    assert resp.status_code == 302
    assert resp.headers["location"] == "/dashboard"

    session_cookie = resp.cookies.get("session_id")
    assert session_cookie is not None

    session = get_session(session_cookie, secondary_storage)
    assert session is not None


@respx.mock
def test_session_callback_rejects_missing_state(client: TestClient):
    mock_token_and_userinfo()
    resp = client.get("/fake/callback", params={"code": "provider-code"})
    assert resp.status_code == 400
    assert resp.json()["error"] == "server_error"


@respx.mock
def test_session_callback_rejects_unknown_state(client: TestClient):
    mock_token_and_userinfo()
    resp = client.get(
        "/fake/callback", params={"code": "provider-code", "state": "never-seen"}
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "server_error"


@respx.mock
def test_session_callback_reports_provider_error(client: TestClient):
    _, state = start_provider_auth(client, "/fake/login")
    resp = client.get(
        "/fake/callback", params={"error": "access_denied", "state": state}
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "access_denied"
