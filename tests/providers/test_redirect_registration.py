"""OAuth server callbacks are registered exactly and belong to a specific client."""

import json
from typing import cast
from urllib.parse import parse_qs, urlparse

import pytest
from cross_web import HTTPRequest, TestingHTTPRequestAdapter

from cross_auth import OAuthClient, OAuthServer
from cross_auth._auth_flow import start_link_flow, start_token_flow
from cross_auth._context import Context
from cross_auth._config import Config


CALLBACK = "http://valid-frontend.com/callback"


def initiate(provider, context, flow, client_id, redirect_uri):
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "code_challenge": "challenge",
        "code_challenge_method": "S256",
        "state": "client-state",
    }
    request = HTTPRequest(
        TestingHTTPRequestAdapter(
            method="GET" if flow == "token" else "POST",
            url=f"http://localhost/test/{'authorize' if flow == 'token' else 'link'}",
            query_params=params if flow == "token" else {},
            body=json.dumps(params).encode() if flow == "link" else b"",
            headers={"Authorization": "Bearer test"},
        )
    )
    handler = start_token_flow if flow == "token" else start_link_flow
    return handler(provider, request, context)


@pytest.fixture
def clients():
    return {
        "dashboard": OAuthClient(client_id="dashboard", redirect_uris=(CALLBACK,)),
        "other-app": OAuthClient(
            client_id="other-app",
            redirect_uris=("http://valid-frontend.com/other-callback",),
        ),
    }


@pytest.fixture
def registered_context(context, clients):
    context.config = {"account_linking": {"enabled": True}}
    context.oauth_server = OAuthServer(get_client=clients.get)
    return context


@pytest.mark.parametrize("flow", ["token", "link"])
@pytest.mark.parametrize(
    "redirect_uri",
    [
        "http://valid-frontend.com/other-callback",
        "http://valid-frontend.com/unregistered",
        "https://valid-frontend.com/callback",
        "http://valid-frontend.com/callback/",
        "http://valid-frontend.com/callback?next=evil",
        "http://valid-frontend.com/callback#fragment",
        "http://valid-frontend.com:80/callback",
        "http://VALID-FRONTEND.com/callback",
        "http://valid-frontend.com/%63allback",
        "http://valid-frontend.com/a/../callback",
        "javascript://valid-frontend.com/callback",
        "//valid-frontend.com/callback",
    ],
)
def test_unregistered_redirect_is_rejected_locally(
    oauth_provider, registered_context, flow, redirect_uri
):
    response = initiate(
        oauth_provider, registered_context, flow, "dashboard", redirect_uri
    )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_redirect_uri"
    assert not response.headers or "Location" not in response.headers


@pytest.mark.parametrize("flow", ["token", "link"])
def test_unknown_client_cannot_use_another_clients_redirect(
    oauth_provider, registered_context, flow
):
    response = initiate(oauth_provider, registered_context, flow, "unknown", CALLBACK)

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_client"
    assert not response.headers or "Location" not in response.headers


@pytest.mark.parametrize("flow", ["token", "link"])
def test_missing_registration_fails_closed(
    oauth_provider, registered_context, clients, flow
):
    clients.clear()

    response = initiate(oauth_provider, registered_context, flow, "dashboard", CALLBACK)

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_client"


@pytest.mark.parametrize("flow", ["token", "link"])
@pytest.mark.parametrize(
    "uri",
    [
        CALLBACK,
        "https://other-host.example",
        "https://other-host.example/callback?app=web",
    ],
)
def test_exact_registered_callback_succeeds(
    oauth_provider, registered_context, clients, secondary_storage, flow, uri
):
    clients["dashboard"] = OAuthClient(client_id="dashboard", redirect_uris=(uri,))
    response = initiate(oauth_provider, registered_context, flow, "dashboard", uri)

    assert response.status_code == (302 if flow == "token" else 200)
    url = (
        response.headers["Location"]
        if flow == "token"
        else response.json()["authorization_url"]
    )
    state = parse_qs(urlparse(url).query)["state"][0]
    stored = json.loads(
        secondary_storage.get(f"oauth:authorization_request:v2:{state}")
    )
    assert stored["client_redirect_uri"] == uri


@pytest.mark.parametrize(
    "uri",
    [
        "javascript://valid-frontend.com/callback",
        "//valid-frontend.com/callback",
        "https://user:password@valid-frontend.com/callback",
        "https://valid-frontend.com/callback#fragment",
        "https://valid-frontend.com/callback#",
        " https://valid-frontend.com/callback",
        "https://valid-frontend.com/call\nback",
        "https://valid-frontend.com\\evil/callback",
    ],
)
def test_invalid_callback_registration_fails_at_startup(uri):
    with pytest.raises(ValueError):
        OAuthClient(client_id="dashboard", redirect_uris=(uri,))


@pytest.mark.parametrize(
    "config", [{"allowed_client_ids": ["dashboard"]}, {"client_redirect_uris": {}}]
)
def test_removed_client_registry_config_is_rejected(context, config):
    with pytest.raises(ValueError, match="Unknown config keys"):
        Context(
            secondary_storage=context.secondary_storage,
            accounts_storage=context.accounts_storage,
            get_user_from_request=context.get_user_from_request,
            config=cast(Config, config),
        )
