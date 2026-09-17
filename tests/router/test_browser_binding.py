import json
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

import pytest
import respx
from fastapi import FastAPI
from fastapi.testclient import TestClient

from cross_auth.models.oauth_token_response import TokenResponse
from cross_auth.social_providers.apple import AppleProvider

from .conftest import (
    load_auth_request,
    FakeProvider,
    mock_token_and_userinfo,
    start_provider_auth,
)


@respx.mock
def test_callback_requires_initiating_browser(
    client, secondary_storage, session_storage
):
    mock_token_and_userinfo(email="browser@example.com")
    _, state = start_provider_auth(client, "/fake/login")

    with TestClient(client.app, follow_redirects=False) as other_browser:
        response = other_browser.get(
            "/fake/callback", params={"code": "provider-code", "state": state}
        )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"
    assert not session_storage.records
    assert secondary_storage.get(f"oauth:authorization_request:v2:{state}") is not None

    response = client.get(
        "/fake/callback", params={"code": "provider-code", "state": state}
    )
    assert response.status_code == 302
    assert response.cookies.get("session_id")
    assert secondary_storage.get(f"oauth:authorization_request:v2:{state}") is None


@respx.mock
def test_connect_requires_current_user_at_callback(client, accounts_storage):
    mock_token_and_userinfo(provider_user_id="connected-browser")
    response = client.get("/fake/connect", headers={"Authorization": "Bearer test"})
    state = parse_qs(urlparse(response.headers["location"]).query)["state"][0]

    response = client.get(
        "/fake/callback", params={"code": "provider-code", "state": state}
    )
    assert response.status_code == 403
    assert (
        accounts_storage.find_social_account(
            provider="fake", provider_user_id="connected-browser"
        )
        is None
    )


def test_cookie_is_secure_and_scoped_to_one_attempt(client):
    with TestClient(
        client.app, base_url="https://testserver", follow_redirects=False
    ) as browser:
        response, state = start_provider_auth(browser, "/fake/login")
        cookie = response.headers["set-cookie"]
        assert f"__Host-cross_auth_oauth_{state}=" in cookie
        for flag in ("HttpOnly", "Secure", "SameSite=lax", "Max-Age=600", "Path=/"):
            assert flag in cookie
        assert "Domain=" not in cookie


@respx.mock
def test_parallel_tabs_and_replay(client, session_storage):
    mock_token_and_userinfo(email="tabs@example.com")
    _, first = start_provider_auth(client, "/fake/login")
    _, second = start_provider_auth(client, "/fake/login")
    for state in (second, first):
        response = client.get("/fake/callback", params={"code": "code", "state": state})
        assert response.status_code == 302
        assert response.cookies.get("session_id")
        assert f"cross_auth_oauth_{state}" not in client.cookies
        assert "Max-Age=0" in response.headers.get_list("set-cookie")[-1]
    assert len(session_storage.records) == 2
    client.get("/fake/callback", params={"code": "code", "state": first})
    assert len(session_storage.records) == 2


@respx.mock
def test_wrong_cookie_does_not_consume_state(client, secondary_storage):
    _, state = start_provider_auth(client, "/fake/login")
    client.cookies.clear()
    client.cookies.set(f"cross_auth_oauth_{state}", "wrong")
    response = client.get("/fake/callback", params={"code": "code", "state": state})
    assert response.status_code == 400
    assert secondary_storage.get(f"oauth:authorization_request:v2:{state}") is not None
    assert not respx.calls


@pytest.mark.parametrize(
    "invalid_field",
    ["expired", "missing_binding", "missing_expiry", "null_binding", "null_expiry"],
)
@respx.mock
def test_invalid_auth_requests_cannot_sign_in(client, secondary_storage, invalid_field):
    _, state = start_provider_auth(client, "/fake/login")
    key = f"oauth:authorization_request:v2:{state}"
    data = json.loads(secondary_storage.get(key))

    if invalid_field == "expired":
        data["expires_at"] = (
            datetime.now(timezone.utc) - timedelta(seconds=1)
        ).isoformat()
    else:
        action, field = invalid_field.split("_", 1)
        field = "browser_binding" if field == "binding" else "expires_at"
        if action == "missing":
            data.pop(field)
        else:
            data[field] = None

    secondary_storage.set(key, json.dumps(data))

    response = client.get("/fake/callback", params={"code": "code", "state": state})

    assert "error=session_expired" in response.headers["location"]
    assert not respx.calls


@respx.mock
def test_provider_error_requires_browser_and_clears_cookie(client, secondary_storage):
    _, state = start_provider_auth(client, "/fake/login")
    with TestClient(client.app, follow_redirects=False) as other:
        response = other.get(
            "/fake/callback", params={"error": "access_denied", "state": state}
        )
        assert response.json()["error"] == "invalid_request"
    response = client.get(
        "/fake/callback", params={"error": "access_denied", "state": state}
    )
    assert response.json()["error"] == "access_denied"
    assert f"cross_auth_oauth_{state}" not in client.cookies
    assert secondary_storage.get(f"oauth:authorization_request:v2:{state}") is None


@respx.mock
def test_wrong_provider_does_not_consume_state(build_auth, secondary_storage):
    other = FakeProvider(client_id="other")
    other.id = "other"
    original = FakeProvider(client_id="fake")
    auth = build_auth(providers=[original, other])
    app = FastAPI()
    app.include_router(auth.router)
    with TestClient(app, follow_redirects=False) as browser:
        _, state = start_provider_auth(browser, "/fake/login")
        response = browser.get(
            "/other/callback", params={"code": "code", "state": state}
        )
        assert response.json()["error_description"] == "Provider mismatch"
        assert (
            secondary_storage.get(f"oauth:authorization_request:v2:{state}") is not None
        )
        mock_token_and_userinfo(email="provider@example.com")
        assert browser.get(
            "/fake/callback", params={"code": "code", "state": state}
        ).cookies.get("session_id")


@respx.mock
def test_token_callback_requires_browser(client, secondary_storage):
    _, state = start_provider_auth(
        client,
        "/fake/authorize",
        params={
            "client_id": "app-client",
            "redirect_uri": "http://client.example/cb",
            "state": "client-state",
            "response_type": "code",
            "code_challenge": "challenge",
            "code_challenge_method": "S256",
        },
    )
    with TestClient(client.app, follow_redirects=False) as other:
        response = other.get("/fake/callback", params={"code": "code", "state": state})
        assert response.status_code == 400
    assert not any(key.startswith("oauth:code:") for key in secondary_storage.data)
    mock_token_and_userinfo(email="token-browser@example.com")
    response = client.get("/fake/callback", params={"code": "code", "state": state})
    assert "code=" in response.headers["location"]


@respx.mock
def test_apple_form_post_waits_for_browser_cookie(
    build_auth, secondary_storage, monkeypatch
):
    provider = AppleProvider(
        client_id="apple-client", team_id="team", key_id="key", private_key="unused"
    )
    exchanged = []
    extras = []

    def exchange(*args):
        exchanged.append(args)
        return TokenResponse(access_token="apple-access", token_type="Bearer")

    def fetch(token, context, extra, *, provider_data):
        assert provider_data["nonce"] == expected_nonce
        extras.append(extra)
        return {
            "id": "apple-user",
            "email": "apple@example.com",
            "email_verified": True,
        }

    monkeypatch.setattr(provider, "exchange_code", exchange)
    monkeypatch.setattr(provider, "fetch_user_info", fetch)
    auth = build_auth(providers=[provider])
    app = FastAPI()
    app.include_router(auth.router)
    with TestClient(
        app, base_url="https://testserver", follow_redirects=False
    ) as browser:
        _, state = start_provider_auth(browser, "/apple/login")
        expected_nonce = load_auth_request(secondary_storage, state).provider_data[
            "nonce"
        ]
        # Simulate the POST arriving without the browser's SameSite=Lax cookie.
        with TestClient(
            app, base_url="https://testserver", follow_redirects=False
        ) as post_browser:
            response = post_browser.post(
                "/apple/callback",
                data={
                    "state": state,
                    "code": "private-code",
                    "user": json.dumps({"name": {"firstName": "Alice"}}),
                },
            )
        assert response.status_code == 303
        assert "private-code" not in response.headers["location"]
        assert "Alice" not in response.headers["location"]
        assert not exchanged
        continuation = response.headers["location"]
        with TestClient(
            app, base_url="https://testserver", follow_redirects=False
        ) as other:
            rejected = other.get(continuation)
            assert rejected.status_code == 400
        response = browser.get(continuation)
        assert response.cookies.get("session_id")
        assert browser.get(continuation).status_code == 400
        assert len(exchanged) == 1
        assert extras == [{"user": {"name": {"firstName": "Alice"}}}]
        assert secondary_storage.get(f"oauth:authorization_request:v2:{state}") is None


@pytest.mark.parametrize("flow", ["connect", "link"])
@respx.mock
def test_account_switch_rejects_callback(
    flow, build_auth, accounts_storage, monkeypatch
):
    from dataclasses import replace

    auth = build_auth(config={"account_linking": {"enabled": True}})
    app = FastAPI()
    app.include_router(auth.router)
    with TestClient(app, follow_redirects=False) as browser:
        if flow == "connect":
            response = browser.get(
                "/fake/connect", headers={"Authorization": "Bearer test"}
            )
            url = response.headers["location"]
        else:
            response = browser.post(
                "/fake/link",
                headers={"Authorization": "Bearer test"},
                json={
                    "client_id": "app-client",
                    "redirect_uri": "http://client.example/cb",
                    "code_challenge": "challenge",
                    "code_challenge_method": "S256",
                },
            )
            url = response.json()["authorization_url"]
        state = parse_qs(urlparse(url).query)["state"][0]
        other_user = replace(accounts_storage.find_user_by_id("test"), id="other")
        monkeypatch.setattr(
            auth._router.context, "get_user_from_request", lambda request: other_user
        )
        response = browser.get(
            "/fake/callback", params={"code": "code", "state": state}
        )
        assert response.status_code == 403
        assert not respx.calls


@respx.mock
def test_link_callback_cannot_transfer_between_browsers(build_auth, secondary_storage):
    auth = build_auth(config={"account_linking": {"enabled": True}})
    app = FastAPI()
    app.include_router(auth.router)
    with TestClient(app, follow_redirects=False) as browser:
        response = browser.post(
            "/fake/link",
            headers={"Authorization": "Bearer test"},
            json={
                "client_id": "app-client",
                "redirect_uri": "http://client.example/cb",
                "code_challenge": "challenge",
                "code_challenge_method": "S256",
            },
        )
        state = parse_qs(urlparse(response.json()["authorization_url"]).query)["state"][
            0
        ]
        with TestClient(app, follow_redirects=False) as other:
            response = other.get(
                "/fake/callback", params={"code": "code", "state": state}
            )
            assert response.status_code == 400
        assert not any(
            key.startswith("oauth:link_request:v2:") for key in secondary_storage.data
        )
        response = browser.get(
            "/fake/callback", params={"code": "code", "state": state}
        )
        assert "link_code=" in response.headers["location"]
