"""Browser OIDC nonces follow the attempt through callback and link redemption."""

from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import respx
from fastapi import FastAPI
from fastapi.testclient import TestClient

from cross_auth._auth_flow import LinkCodeData
from cross_auth.social_providers.oidc import OIDCProvider
from cross_auth.social_providers.oauth import CallbackData

from .conftest import load_auth_request
from .test_link_flow import _LINK_CODE_CHALLENGE, _LINK_CODE_VERIFIER
from .test_token_flow import _AUTHZ_PARAMS


class NonceProvider(OIDCProvider):
    id = "fake"
    authorization_endpoint = "https://fake.example/oauth/authorize"
    token_endpoint = "https://fake.example/oauth/token"
    scopes = ["openid"]
    supports_pkce = True
    claims: dict[str, Any]

    def extract_callback_params(self, request):
        if request.method == "POST":
            return CallbackData(
                error=None,
                code=request.post_data.get("code"),
                state=request.post_data.get("state"),
            )
        return super().extract_callback_params(request)

    def validate_id_token(self, id_token, secondary_storage):
        # Signature/claim validation has independent signed-token provider tests.
        return self.claims


@pytest.fixture
def oidc_client(build_auth):
    provider = NonceProvider(
        client_id="client",
        client_secret="secret",
        extra_authorization_params={"nonce": "static-value", "prompt": "consent"},
    )
    provider.claims = {
        "sub": "identity",
        "email": "test@example.com",
        "email_verified": True,
    }
    auth = build_auth(
        providers=[provider],
        config={
            "session": {"cookies": {"auth": True}},
            "account_linking": {"enabled": True},
        },
    )
    app = FastAPI()
    app.include_router(auth.router)
    with TestClient(app, follow_redirects=False) as client:
        yield client, provider


def _start(client, flow):
    if flow == "link":
        response = client.post(
            "/fake/link",
            headers={"Authorization": "Bearer test"},
            json={
                "client_id": "app-client",
                "redirect_uri": "http://client.example/cb",
                "code_challenge": _LINK_CODE_CHALLENGE,
                "code_challenge_method": "S256",
            },
        )
        assert response.status_code == 200
        url = response.json()["authorization_url"]
    else:
        path = {"session": "login", "token": "authorize", "connect": "connect"}[flow]
        response = client.get(
            f"/fake/{path}",
            params=_AUTHZ_PARAMS if flow == "token" else None,
            headers={"Authorization": "Bearer test"},
        )
        assert response.status_code == 302
        url = response.headers["location"]
    params = parse_qs(urlparse(url).query)
    return params["state"][0], params["nonce"][0]


def _callback(client, state):
    return client.get(
        "/fake/callback",
        params={"state": state, "code": "provider-code"},
        headers={"Authorization": "Bearer test"},
    )


def _tokens():
    return respx.post("https://fake.example/oauth/token").mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "access",
                "token_type": "Bearer",
                "id_token": "signed-token",
            },
        )
    )


@pytest.mark.parametrize("flow", ["session", "token", "connect", "link"])
def test_each_oidc_attempt_stores_a_fresh_managed_nonce(
    oidc_client, secondary_storage, flow
):
    client, _ = oidc_client
    state, nonce = _start(client, flow)
    other_state, other_nonce = _start(client, flow)

    assert nonce != other_nonce
    assert nonce != "static-value"
    assert load_auth_request(secondary_storage, state).provider_data["nonce"] == nonce
    assert (
        load_auth_request(secondary_storage, other_state).provider_data["nonce"]
        == other_nonce
    )


@pytest.mark.parametrize("flow", ["session", "token", "connect"])
@pytest.mark.parametrize("claim", [None, "wrong", "match"])
@respx.mock
def test_oidc_callback_verifies_nonce_before_account_updates(
    oidc_client, accounts_storage, flow, claim
):
    client, provider = oidc_client
    state, nonce = _start(client, flow)
    if claim is not None:
        provider.claims["nonce"] = nonce if claim == "match" else claim
    _tokens()

    response = _callback(client, state)

    if claim == "match":
        assert response.status_code == 302
        assert len(accounts_storage.data["test"].social_accounts) == 1
    else:
        if flow == "token":
            assert parse_qs(urlparse(response.headers["location"]).query)["error"] == [
                "invalid_token"
            ]
        else:
            assert response.status_code == 400
            assert response.json()["error"] == "invalid_token"
        assert accounts_storage.data["test"].social_accounts == []


@pytest.mark.parametrize("claim", [None, "wrong", "match", "missing_stored_nonce"])
@respx.mock
def test_oidc_link_preserves_nonce_and_checks_it_at_finalization(
    oidc_client, secondary_storage, accounts_storage, claim
):
    client, provider = oidc_client
    state, nonce = _start(client, "link")
    response = _callback(client, state)
    link_code = parse_qs(urlparse(response.headers["location"]).query)["link_code"][0]
    key = f"oauth:link_request:v2:{link_code}"
    data = LinkCodeData.model_validate_json(secondary_storage.get(key))
    assert data.provider_data["nonce"] == nonce
    if claim == "missing_stored_nonce":
        data.provider_data.pop("nonce")
        secondary_storage.set(key, data.model_dump_json())
    elif claim is not None:
        provider.claims["nonce"] = nonce if claim == "match" else claim
    token_route = _tokens()

    response = client.post(
        "/fake/finalize-link",
        headers={"Authorization": "Bearer test"},
        json={"link_code": link_code, "code_verifier": _LINK_CODE_VERIFIER},
    )

    if claim == "match":
        assert response.status_code == 200
        assert len(accounts_storage.data["test"].social_accounts) == 1
    else:
        assert response.status_code == 400
        assert response.json()["error"] == (
            "invalid_request" if claim == "missing_stored_nonce" else "invalid_token"
        )
        assert accounts_storage.data["test"].social_accounts == []
    if claim == "missing_stored_nonce":
        assert token_route.call_count == 0


@respx.mock
def test_oidc_request_without_stored_nonce_requires_restart(
    oidc_client, secondary_storage, accounts_storage
):
    client, _ = oidc_client
    state, _ = _start(client, "session")
    request = load_auth_request(secondary_storage, state)
    request.provider_data.pop("nonce")
    secondary_storage.set(
        f"oauth:authorization_request:v2:{state}", request.model_dump_json()
    )
    token_route = _tokens()

    response = _callback(client, state)

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"
    assert token_route.call_count == 0
    assert accounts_storage.data["test"].social_accounts == []


@pytest.mark.parametrize("matches", [True, False])
@respx.mock
def test_oidc_form_post_continuation_verifies_nonce(
    oidc_client, accounts_storage, matches
):
    client, provider = oidc_client
    state, nonce = _start(client, "session")
    provider.claims["nonce"] = nonce if matches else "wrong"
    token_route = _tokens()

    with TestClient(client.app, follow_redirects=False) as form_browser:
        response = form_browser.post(
            "/fake/callback", data={"code": "provider-code", "state": state}
        )

    assert response.status_code == 303
    assert token_route.call_count == 0
    response = client.get(response.headers["location"])

    if matches:
        assert response.status_code == 302
        assert len(accounts_storage.data["test"].social_accounts) == 1
    else:
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_token"
        assert accounts_storage.data["test"].social_accounts == []
    assert token_route.call_count == 1


@pytest.mark.parametrize("flow", ["session", "token", "connect", "link"])
@respx.mock
def test_provider_data_survives_until_user_info_fetch(
    oidc_client, secondary_storage, monkeypatch, flow
):
    client, provider = oidc_client
    get_data = provider.get_authorization_data
    fetch_user_info = provider.fetch_user_info
    received = []

    def get_authorization_data():
        return {**get_data(), "private_value": "stored-for-this-attempt"}

    def fetch(token, context, extra, *, provider_data):
        received.append(provider_data)
        return fetch_user_info(token, context, extra, provider_data=provider_data)

    monkeypatch.setattr(provider, "get_authorization_data", get_authorization_data)
    monkeypatch.setattr(provider, "fetch_user_info", fetch)
    state, nonce = _start(client, flow)
    expected = {"nonce": nonce, "private_value": "stored-for-this-attempt"}
    assert load_auth_request(secondary_storage, state).provider_data == expected

    provider.claims["nonce"] = nonce
    _tokens()
    response = _callback(client, state)
    assert response.status_code == 302

    if flow == "link":
        assert received == []
        link_code = parse_qs(urlparse(response.headers["location"]).query)["link_code"][
            0
        ]
        response = client.post(
            "/fake/finalize-link",
            headers={"Authorization": "Bearer test"},
            json={"link_code": link_code, "code_verifier": _LINK_CODE_VERIFIER},
        )
        assert response.status_code == 200

    assert received == [expected]
