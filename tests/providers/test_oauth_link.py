import json
from urllib.parse import parse_qs, urlparse

import pytest
from cross_web import AsyncHTTPRequest, TestingRequestAdapter
from inline_snapshot import snapshot

from cross_auth._context import Context, SecondaryStorage
from cross_auth._storage import AccountsStorage, User
from cross_auth.social_providers.oauth import OAuth2Provider
from tests.conftest import MemoryStorage

# Note: json import still needed for json.loads in test assertions

pytestmark = pytest.mark.asyncio


@pytest.fixture
def context(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    logged_in_user: User,
) -> Context:
    """Override context with account linking enabled for link tests."""

    def _get_user_from_request(request: AsyncHTTPRequest) -> User | None:
        if request.headers.get("Authorization") == "Bearer test":
            return logged_in_user
        return None

    return Context(
        secondary_storage=secondary_storage,
        accounts_storage=accounts_storage,
        create_token=lambda id: (f"token-{id}", 0),
        get_user_from_request=_get_user_from_request,
        trusted_origins=["valid-frontend.com"],
        config={"account_linking": {"enabled": True}},
    )


async def test_initiate_link_stores_correct_request_data(
    oauth_provider: OAuth2Provider,
    context: Context,
    secondary_storage: MemoryStorage,
):
    request = AsyncHTTPRequest(
        TestingRequestAdapter(
            method="POST",
            url="http://localhost:8000/test/link",
            headers={
                "Authorization": "Bearer test",
            },
            json={
                "client_id": "my_app_client_id",
                "redirect_uri": "http://valid-frontend.com/callback",
                "code_challenge": "test",
                "code_challenge_method": "S256",
            },
        )
    )

    response = await oauth_provider.initiate_link(request, context)

    assert response.status_code == 200
    assert response.body

    response_data = json.loads(response.body)
    assert "authorization_url" in response_data

    authorization_url = response_data["authorization_url"]
    assert authorization_url.startswith(oauth_provider.authorization_endpoint)

    query_params = parse_qs(urlparse(authorization_url).query)

    assert query_params["client_id"] == ["test_client_id"]
    assert query_params["scope"] == ["openid email profile"]
    assert query_params["redirect_uri"] == ["http://localhost:8000/test/callback"]

    state = query_params["state"][0]

    data_str = secondary_storage.get(f"oauth:authorization_request:{state}")

    assert data_str

    data = json.loads(data_str)

    assert "provider_code_verifier" in data
    data.pop("provider_code_verifier")

    assert data == snapshot(
        {
            "client_id": "my_app_client_id",
            "redirect_uri": "http://valid-frontend.com/callback",
            "login_hint": None,
            "client_state": None,
            "state": state,
            "code_challenge": "test",
            "code_challenge_method": "S256",
            "link": True,
            "user_id": "test",
            "auth_mode": "code",
        }
    )


async def test_initiate_link_requires_authentication(
    oauth_provider: OAuth2Provider,
    context: Context,
):
    request = AsyncHTTPRequest(
        TestingRequestAdapter(
            method="POST",
            url="http://localhost:8000/test/link",
            json={
                "client_id": "my_app_client_id",
                "redirect_uri": "http://valid-frontend.com/callback",
                "code_challenge": "test",
                "code_challenge_method": "S256",
            },
        )
    )

    response = await oauth_provider.initiate_link(request, context)

    assert response.status_code == 401
    assert response.body
    assert "unauthorized" in response.body


async def test_initiate_link_fails_when_linking_disabled(
    oauth_provider: OAuth2Provider,
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    logged_in_user: User,
):
    def _get_user_from_request(request: AsyncHTTPRequest) -> User | None:
        if request.headers.get("Authorization") == "Bearer test":
            return logged_in_user
        return None

    context = Context(
        secondary_storage=secondary_storage,
        accounts_storage=accounts_storage,
        create_token=lambda id: (f"token-{id}", 0),
        get_user_from_request=_get_user_from_request,
        trusted_origins=["valid-frontend.com"],
        config={"account_linking": {"enabled": False}},
    )

    request = AsyncHTTPRequest(
        TestingRequestAdapter(
            method="POST",
            url="http://localhost:8000/test/link",
            headers={
                "Authorization": "Bearer test",
            },
            json={
                "client_id": "my_app_client_id",
                "redirect_uri": "http://valid-frontend.com/callback",
                "code_challenge": "test",
                "code_challenge_method": "S256",
            },
        )
    )

    response = await oauth_provider.initiate_link(request, context)

    assert response.status_code == 400
    assert response.body
    assert "linking_disabled" in response.body
