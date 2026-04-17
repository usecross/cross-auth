"""Router-level tests for the token (OAuth client) flow: /{provider}/authorize."""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import respx
from fastapi.testclient import TestClient

from cross_auth._issuer import AuthorizationCodeGrantData
from cross_auth._storage import SecondaryStorage

from .conftest import (
    load_auth_request,
    mock_token_and_userinfo,
    start_provider_auth,
)


_AUTHZ_PARAMS = {
    "client_id": "app-client",
    "redirect_uri": "http://client.example/cb",
    "state": "client-csrf-state",
    "response_type": "code",
    "code_challenge": "client-challenge",
    "code_challenge_method": "S256",
}


def test_authorize_stores_client_params(
    client: TestClient, secondary_storage: SecondaryStorage
):
    _, state = start_provider_auth(client, "/fake/authorize", params=_AUTHZ_PARAMS)
    req = load_auth_request(secondary_storage, state)
    assert req.flow == "token"
    assert req.client_id == "app-client"
    assert req.client_redirect_uri == "http://client.example/cb"
    assert req.client_state == "client-csrf-state"
    assert req.client_code_challenge == "client-challenge"
    assert req.client_code_challenge_method == "S256"


def test_authorize_rejects_missing_redirect_uri(client: TestClient):
    resp = client.get("/fake/authorize", params={"response_type": "code"})
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"


def test_authorize_rejects_untrusted_redirect_uri(client: TestClient):
    params = {**_AUTHZ_PARAMS, "redirect_uri": "http://evil.example/cb"}
    resp = client.get("/fake/authorize", params=params)
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_redirect_uri"


def test_authorize_rejects_missing_code_challenge(client: TestClient):
    params = {**_AUTHZ_PARAMS}
    params.pop("code_challenge")
    resp = client.get("/fake/authorize", params=params)
    assert resp.status_code == 302
    location = resp.headers["location"]
    assert "error=invalid_request" in location
    assert "state=client-csrf-state" in location


def test_authorize_rejects_unsupported_challenge_method(client: TestClient):
    params = {**_AUTHZ_PARAMS, "code_challenge_method": "plain"}
    resp = client.get("/fake/authorize", params=params)
    assert resp.status_code == 302
    assert "error=invalid_request" in resp.headers["location"]


@respx.mock
def test_token_callback_mints_authorization_code_and_redirects(
    client: TestClient, secondary_storage: SecondaryStorage
):
    mock_token_and_userinfo(email="bob@example.com", provider_user_id="bob-1")

    _, state = start_provider_auth(client, "/fake/authorize", params=_AUTHZ_PARAMS)

    resp = client.get(
        "/fake/callback", params={"code": "provider-code", "state": state}
    )
    assert resp.status_code == 302

    location = resp.headers["location"]
    parsed = urlparse(location)
    assert (
        f"{parsed.scheme}://{parsed.netloc}{parsed.path}" == "http://client.example/cb"
    )

    qs = parse_qs(parsed.query)
    assert qs["state"] == ["client-csrf-state"]
    code = qs["code"][0]

    stored = secondary_storage.get(f"oauth:code:{code}")
    assert stored is not None
    grant = AuthorizationCodeGrantData.model_validate_json(stored)
    assert grant.client_id == "app-client"
    assert grant.redirect_uri == "http://client.example/cb"
    assert grant.code_challenge == "client-challenge"


@respx.mock
def test_token_callback_reports_provider_error_to_client(client: TestClient):
    _, state = start_provider_auth(client, "/fake/authorize", params=_AUTHZ_PARAMS)

    # Simulate the provider bouncing us back with an error.
    mock_token_and_userinfo()  # not used, but keeps respx happy
    resp = client.get(
        "/fake/callback", params={"error": "access_denied", "state": state}
    )
    # access_denied happens before we look up auth_request, so it returns a plain error.
    assert resp.status_code == 400
    assert resp.json()["error"] == "access_denied"


@respx.mock
def test_token_callback_no_code_redirects_client_with_error(
    client: TestClient,
):
    _, state = start_provider_auth(client, "/fake/authorize", params=_AUTHZ_PARAMS)
    resp = client.get("/fake/callback", params={"state": state})
    # Missing code → client redirect with error_description, preserving state
    assert resp.status_code == 302
    location = resp.headers["location"]
    assert location.startswith("http://client.example/cb")
    assert "error=server_error" in location
    assert "state=client-csrf-state" in location


@respx.mock
def test_token_flow_account_not_linked_when_email_conflicts(
    client: TestClient, accounts_storage
):
    # A user with this email exists (seeded as "test@example.com"); since
    # account_linking is disabled in config, we should get account_not_linked.
    mock_token_and_userinfo(
        email="test@example.com", provider_user_id="new-provider-id"
    )

    _, state = start_provider_auth(client, "/fake/authorize", params=_AUTHZ_PARAMS)
    resp = client.get(
        "/fake/callback", params={"code": "provider-code", "state": state}
    )
    assert resp.status_code == 302
    assert "error=account_not_linked" in resp.headers["location"]
