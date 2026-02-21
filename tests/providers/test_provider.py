import json

import httpx
import pytest
import respx
from cross_web import AsyncHTTPRequest, TestingRequestAdapter

from cross_auth._context import Context
from cross_auth.social_providers.oauth import OAuth2Provider


class ExampleProvider(OAuth2Provider):
    id = "example"

    authorization_endpoint = "https://example.com/login/oauth/authorize"
    token_endpoint = "https://example.com/login/oauth/access_token"
    user_info_endpoint = "https://api.example.com/user"
    scopes = ["user:email"]


class ExampleProviderWithPKCE(OAuth2Provider):
    id = "example_pkce"

    authorization_endpoint = "https://example.com/login/oauth/authorize"
    token_endpoint = "https://example.com/login/oauth/access_token"
    user_info_endpoint = "https://api.example.com/user"
    scopes = ["user:email"]
    supports_pkce = True


@pytest.fixture
def example_provider() -> ExampleProvider:
    return ExampleProvider(
        client_id="test_client_id", client_secret="test_client_secret"
    )


@respx.mock
def test_exchange_code_success(example_provider: ExampleProvider) -> None:
    token_response = {
        "access_token": "gho_test_token_12345",
        "token_type": "bearer",
        "scope": "user:email",
    }

    respx.post("https://example.com/login/oauth/access_token").mock(
        return_value=respx.MockResponse(200, json=token_response)
    )

    result = example_provider.exchange_code("test_code", "https://example.com/callback")

    assert result.access_token == "gho_test_token_12345"
    assert result.token_type == "bearer"


@respx.mock
def test_exchange_code_github_down(example_provider: ExampleProvider):
    from cross_auth.social_providers.oauth import OAuth2Exception

    respx.post("https://example.com/login/oauth/access_token").mock(
        return_value=respx.MockResponse(503)
    )

    with pytest.raises(OAuth2Exception) as exc_info:
        example_provider.exchange_code("test_code", "https://example.com/callback")

    assert exc_info.value.error == "server_error"
    assert "Token exchange failed" in exc_info.value.error_description


@pytest.fixture
def example_provider_with_pkce() -> ExampleProviderWithPKCE:
    return ExampleProviderWithPKCE(
        client_id="test_client_id", client_secret="test_client_secret"
    )


@respx.mock
@pytest.mark.asyncio
async def test_pkce_flow_includes_code_verifier(
    example_provider_with_pkce: ExampleProviderWithPKCE,
    context: Context,
) -> None:
    authorize_request = AsyncHTTPRequest(
        TestingRequestAdapter(
            method="GET",
            url="http://localhost:8000/example_pkce/authorize",
            query_params={
                "client_id": "my_app_client_id",
                "redirect_uri": "http://valid-frontend.com/callback",
                "code_challenge": "client_code_challenge",
                "code_challenge_method": "S256",
                "response_type": "code",
            },
        )
    )

    authorize_response = await example_provider_with_pkce.authorize(
        authorize_request, context
    )

    assert authorize_response.status_code == 302
    assert authorize_response.headers is not None

    location = authorize_response.headers["Location"]
    state = location.split("state=")[1].split("&")[0]

    stored_data = context.secondary_storage.get(f"oauth:authorization_request:{state}")
    assert stored_data is not None
    stored_json = json.loads(stored_data)
    assert "provider_code_verifier" in stored_json
    assert stored_json["provider_code_verifier"] is not None
    stored_verifier = stored_json["provider_code_verifier"]

    callback_request = AsyncHTTPRequest(
        TestingRequestAdapter(
            method="GET",
            url="http://localhost:8000/example_pkce/callback",
            query_params={
                "code": "provider_auth_code",
                "state": state,
            },
        )
    )

    token_response = {
        "access_token": "test_access_token",
        "token_type": "bearer",
        "scope": "user:email",
    }

    token_route = respx.post(example_provider_with_pkce.token_endpoint).mock(
        return_value=httpx.Response(200, json=token_response)
    )

    respx.get(example_provider_with_pkce.user_info_endpoint).mock(
        return_value=httpx.Response(
            200,
            json={"email": "test@example.com", "id": "test_user_id"},
        )
    )

    await example_provider_with_pkce.callback(callback_request, context)

    request_data = token_route.calls[0].request.content.decode()

    assert f"code_verifier={stored_verifier}" in request_data
