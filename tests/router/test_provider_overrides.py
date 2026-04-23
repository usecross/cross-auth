from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import pytest
from cross_web import AsyncHTTPRequest, TestingRequestAdapter
from fastapi import FastAPI
from fastapi.testclient import TestClient

from cross_auth._context import Context
from cross_auth._storage import AccountsStorage, SecondaryStorage, User
from cross_auth.social_providers.oauth import OAuth2Provider, Response

from .conftest import FakeProvider, _build_auth, load_auth_request


class CustomRouteProvider(FakeProvider):
    async def callback(self, request: AsyncHTTPRequest, context: Context) -> Response:
        return Response(status_code=204)

    async def initiate_link(
        self, request: AsyncHTTPRequest, context: Context
    ) -> Response:
        return Response(
            status_code=200,
            body='{"installation_url":"https://example.com/install"}',
            headers={"Content-Type": "application/json"},
        )


def _make_client(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    provider: OAuth2Provider,
) -> TestClient:
    auth = _build_auth(
        storage=secondary_storage,
        accounts_storage=accounts_storage,
        providers=[provider],
        config={"account_linking": {"enabled": True}},
    )
    app = FastAPI()
    app.include_router(auth.router)
    return TestClient(app, follow_redirects=False)


def test_router_uses_provider_callback_override(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
) -> None:
    provider = CustomRouteProvider(
        client_id="custom-client-id",
        client_secret="custom-secret",
    )

    with _make_client(secondary_storage, accounts_storage, provider) as client:
        response = client.get("/fake/callback")

    assert response.status_code == 204


def test_router_uses_provider_link_override(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
) -> None:
    provider = CustomRouteProvider(
        client_id="custom-client-id",
        client_secret="custom-secret",
    )

    with _make_client(secondary_storage, accounts_storage, provider) as client:
        response = client.post("/fake/link")

    assert response.status_code == 200
    assert response.json() == {"installation_url": "https://example.com/install"}


@pytest.mark.asyncio
async def test_prepare_link_returns_state_and_authorization_url(
    fake_provider: FakeProvider,
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
) -> None:
    def resolve_user(request: AsyncHTTPRequest) -> User | None:
        if request.headers.get("Authorization") == "Bearer test":
            return accounts_storage.find_user_by_id("test")
        return None

    context = Context(
        secondary_storage=secondary_storage,
        accounts_storage=accounts_storage,
        create_token=lambda user_id: (f"token-{user_id}", 0),
        trusted_origins=["client.example"],
        get_user_from_request=resolve_user,
        config={"account_linking": {"enabled": True}},
    )

    request = AsyncHTTPRequest(
        TestingRequestAdapter(
            method="POST",
            url="http://localhost:8000/fake/link",
            headers={"Authorization": "Bearer test"},
            json={
                "redirect_uri": "http://client.example/cb",
                "code_challenge": "challenge",
                "code_challenge_method": "S256",
                "client_id": "app-client",
                "state": "client-state",
            },
        )
    )

    prepared = await fake_provider.prepare_link(request, context)

    qs = parse_qs(urlparse(prepared.authorization_url).query)
    assert prepared.state == qs["state"][0]
    assert prepared.authorization_url.startswith("https://fake.example/oauth/authorize")

    auth_request = load_auth_request(secondary_storage, prepared.state)
    assert auth_request.flow == "link"
    assert auth_request.client_state == "client-state"
    assert auth_request.client_redirect_uri == "http://client.example/cb"
