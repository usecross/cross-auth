"""Router-level tests for the connect flow: GET /{provider}/connect.

Connect is "session-flavored link": a logged-in user attaches a social account
via a single GET round-trip (no PKCE with the client).
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import respx
from fastapi.testclient import TestClient

from cross_auth._storage import SecondaryStorage

from .conftest import load_auth_request, mock_token_and_userinfo


def test_connect_requires_authentication(client: TestClient):
    resp = client.get("/fake/connect")
    assert resp.status_code == 401
    assert resp.json()["error"] == "unauthorized"


def test_connect_redirects_to_provider_when_logged_in(
    client: TestClient, secondary_storage: SecondaryStorage
):
    resp = client.get(
        "/fake/connect",
        params={"next": "/profile"},
        headers={"Authorization": "Bearer test"},
    )
    assert resp.status_code == 302
    location = resp.headers["location"]
    assert location.startswith("https://fake.example/oauth/authorize")

    state = parse_qs(urlparse(location).query)["state"][0]
    req = load_auth_request(secondary_storage, state)
    assert req.flow == "connect"
    assert req.user_id == "test"
    assert req.next_url == "/profile"


def test_connect_rejects_unsafe_next(
    client: TestClient, secondary_storage: SecondaryStorage
):
    resp = client.get(
        "/fake/connect",
        params={"next": "https://evil.example/steal"},
        headers={"Authorization": "Bearer test"},
    )
    state = parse_qs(urlparse(resp.headers["location"]).query)["state"][0]
    assert load_auth_request(secondary_storage, state).next_url == "/"


@respx.mock
def test_connect_callback_attaches_social_account_and_redirects(
    client: TestClient, accounts_storage
):
    mock_token_and_userinfo(email="demo@example.com", provider_user_id="fake-123")

    resp = client.get(
        "/fake/connect",
        params={"next": "/profile"},
        headers={"Authorization": "Bearer test"},
    )
    state = parse_qs(urlparse(resp.headers["location"]).query)["state"][0]

    callback = client.get(
        "/fake/callback", params={"code": "provider-code", "state": state}
    )
    assert callback.status_code == 302
    assert callback.headers["location"] == "/profile"

    user = accounts_storage.find_user_by_id("test")
    social = [a for a in user.social_accounts if a.provider == "fake"]
    assert len(social) == 1
    assert social[0].provider_user_id == "fake-123"
    # Connect doesn't promote to a login method — existing session still auths.
    assert social[0].is_login_method is False


@respx.mock
def test_connect_callback_updates_existing_account_for_same_user(
    client: TestClient, accounts_storage
):
    mock_token_and_userinfo(email="demo@example.com", provider_user_id="fake-123")

    # First connect — creates the social account.
    r1 = client.get(
        "/fake/connect",
        params={"next": "/profile"},
        headers={"Authorization": "Bearer test"},
    )
    state1 = parse_qs(urlparse(r1.headers["location"]).query)["state"][0]
    client.get("/fake/callback", params={"code": "c1", "state": state1})

    # Second connect — should update, not error or duplicate.
    r2 = client.get(
        "/fake/connect",
        params={"next": "/profile"},
        headers={"Authorization": "Bearer test"},
    )
    state2 = parse_qs(urlparse(r2.headers["location"]).query)["state"][0]
    r2_cb = client.get("/fake/callback", params={"code": "c2", "state": state2})

    assert r2_cb.status_code == 302
    assert r2_cb.headers["location"] == "/profile"

    user = accounts_storage.find_user_by_id("test")
    social = [a for a in user.social_accounts if a.provider == "fake"]
    assert len(social) == 1  # still only one


@respx.mock
def test_connect_callback_errors_if_account_belongs_to_another_user(
    client: TestClient, accounts_storage, test_password_hash
):
    # Seed a *different* user who already owns the fake-123 provider account.
    from tests.conftest import SocialAccount, User as DemoUser

    other = DemoUser(
        id="other-user",
        email="other@example.com",
        email_verified=True,
        hashed_password=test_password_hash,
        social_accounts=[
            SocialAccount(
                id="existing",
                user_id="other-user",
                provider="fake",
                provider_user_id="fake-123",
            )
        ],
    )
    accounts_storage.data["other-user"] = other

    mock_token_and_userinfo(email="demo@example.com", provider_user_id="fake-123")

    resp = client.get(
        "/fake/connect",
        headers={"Authorization": "Bearer test"},
    )
    state = parse_qs(urlparse(resp.headers["location"]).query)["state"][0]

    callback = client.get("/fake/callback", params={"code": "code", "state": state})
    assert callback.status_code == 400
    assert callback.json()["error"] == "account_already_linked"

    # "test" user should still have no social account.
    test_user = accounts_storage.find_user_by_id("test")
    assert [a for a in test_user.social_accounts if a.provider == "fake"] == []
