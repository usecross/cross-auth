import json
import logging

import httpx
import pytest
import respx
from cross_web import HTTPRequest, TestingHTTPRequestAdapter

from cross_auth import TokenResponse
from cross_auth._auth_flow import handle_callback, start_token_flow
from cross_auth._context import Context
from cross_auth.models.oauth_token_response import TokenErrorResponse
from cross_auth.social_providers.oauth import (
    OAuth2Exception,
    OAuth2Provider,
    OAuth2TimeoutException,
    logger,
)


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


class ExampleProviderWithCustomTokenParser(ExampleProvider):
    def parse_token_response(
        self, response: httpx.Response
    ) -> TokenResponse | TokenErrorResponse:
        data = response.json()
        return TokenResponse.model_validate(data["tokens"])


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


@pytest.mark.parametrize(
    ("payload", "expected_type"),
    [
        (
            {
                "access_token": "gho_test_token_12345",
                "token_type": "bearer",
            },
            TokenResponse,
        ),
        ({"error": "invalid_grant"}, TokenErrorResponse),
    ],
)
def test_parse_token_response_returns_wire_model_directly(
    example_provider: ExampleProvider,
    payload: dict[str, str],
    expected_type: type[TokenResponse] | type[TokenErrorResponse],
) -> None:
    result = example_provider.parse_token_response(httpx.Response(200, json=payload))

    assert type(result) is expected_type


def test_parse_token_response_preserves_success_precedence(
    example_provider: ExampleProvider,
) -> None:
    response = httpx.Response(
        200,
        json={
            "access_token": "gho_test_token_12345",
            "token_type": "bearer",
            "error": "invalid_grant",
        },
    )

    result = example_provider.parse_token_response(response)

    assert isinstance(result, TokenResponse)
    assert result.access_token == "gho_test_token_12345"


@respx.mock
def test_exchange_code_supports_direct_custom_parser_response() -> None:
    provider = ExampleProviderWithCustomTokenParser(
        client_id="test_client_id", client_secret="test_client_secret"
    )
    respx.post(provider.token_endpoint).mock(
        return_value=respx.MockResponse(
            200,
            json={
                "tokens": {
                    "access_token": "custom_token",
                    "token_type": "bearer",
                }
            },
        )
    )

    result = provider.exchange_code("test_code", "https://example.com/callback")

    assert isinstance(result, TokenResponse)
    assert result.access_token == "custom_token"


@respx.mock
def test_exchange_code_github_down(
    example_provider: ExampleProvider,
    caplog: pytest.LogCaptureFixture,
) -> None:
    respx.post("https://example.com/login/oauth/access_token").mock(
        return_value=respx.MockResponse(503)
    )

    with (
        caplog.at_level(logging.WARNING, logger=logger.name),
        pytest.raises(OAuth2Exception) as exc_info,
    ):
        example_provider.exchange_code("test_code", "https://example.com/callback")

    assert exc_info.value.error == "server_error"
    assert "Token exchange failed" in exc_info.value.error_description
    provider_records = [
        record for record in caplog.records if record.name == logger.name
    ]
    assert len(provider_records) == 1
    assert provider_records[0].levelno == logging.WARNING
    assert provider_records[0].getMessage() == (
        "HTTP error during token exchange: 503 - "
    )


@respx.mock
def test_exchange_code_logs_malformed_success_response(
    example_provider: ExampleProvider,
    caplog: pytest.LogCaptureFixture,
) -> None:
    respx.post("https://example.com/login/oauth/access_token").mock(
        return_value=respx.MockResponse(
            200,
            json={"access_token": "gho_test_token_12345"},
        )
    )

    with (
        caplog.at_level(logging.ERROR, logger=logger.name),
        pytest.raises(OAuth2Exception) as exc_info,
    ):
        example_provider.exchange_code("test_code", "https://example.com/callback")

    assert exc_info.value.error == "server_error"
    assert exc_info.value.error_description == "Failed to parse token response"
    provider_records = [
        record for record in caplog.records if record.name == logger.name
    ]
    assert len(provider_records) == 1
    assert provider_records[0].levelno == logging.ERROR
    assert (
        provider_records[0]
        .getMessage()
        .startswith("Failed to parse token response: 2 validation errors")
    )


@respx.mock
def test_exchange_code_reports_timeout_without_retrying(
    caplog: pytest.LogCaptureFixture,
) -> None:
    provider = ExampleProvider(
        client_id="test_client_id",
        client_secret="test_client_secret",
        token_exchange_timeout=15.0,
    )
    token_route = respx.post(provider.token_endpoint).mock(
        side_effect=httpx.ReadTimeout("provider timed out")
    )

    with (
        caplog.at_level(logging.WARNING, logger=logger.name),
        pytest.raises(OAuth2TimeoutException) as exc_info,
    ):
        provider.exchange_code("test_code", "https://example.com/callback")

    assert token_route.call_count == 1
    assert token_route.calls[0].request.extensions["timeout"]["read"] == 15.0
    assert exc_info.value.error == "temporarily_unavailable"
    assert exc_info.value.error_description == (
        "The OAuth provider timed out. Please restart the authorization flow."
    )
    assert str(exc_info.value) == exc_info.value.error_description
    assert len(caplog.records) == 1
    assert caplog.records[0].levelno == logging.WARNING
    assert getattr(caplog.records[0], "oauth_provider") == "example"
    assert getattr(caplog.records[0], "oauth_error") == "temporarily_unavailable"
    assert caplog.records[0].getMessage() == "Token exchange timed out"


@pytest.mark.parametrize(
    "status_code",
    [200, 400],
)
@respx.mock
def test_exchange_code_preserves_recoverable_provider_error(
    example_provider: ExampleProvider,
    caplog: pytest.LogCaptureFixture,
    status_code: int,
) -> None:
    error = "bad_verification_code"
    respx.post("https://example.com/login/oauth/access_token").mock(
        return_value=respx.MockResponse(
            status_code,
            json={
                "error": error,
                "error_description": "The code is invalid or expired.",
            },
        )
    )

    with (
        caplog.at_level(logging.INFO, logger=logger.name),
        pytest.raises(OAuth2Exception) as exc_info,
    ):
        example_provider.exchange_code("test_code", "https://example.com/callback")

    assert exc_info.value.error == error
    assert exc_info.value.error_description == "The code is invalid or expired."
    assert len(caplog.records) == 1
    assert caplog.records[0].name == logger.name
    assert caplog.records[0].levelno == logging.INFO
    assert getattr(caplog.records[0], "oauth_provider") == "example"
    assert getattr(caplog.records[0], "oauth_error") == error
    assert (
        caplog.records[0].getMessage()
        == f"Token exchange rejected by provider: {error}"
    )


@respx.mock
def test_exchange_code_rejects_nonrecoverable_provider_error(
    example_provider: ExampleProvider,
    caplog: pytest.LogCaptureFixture,
) -> None:
    respx.post("https://example.com/login/oauth/access_token").mock(
        return_value=respx.MockResponse(
            200,
            json={
                "error": "invalid_grant",
                "error_description": "The grant is invalid.",
            },
        )
    )

    with (
        caplog.at_level(logging.ERROR, logger=logger.name),
        pytest.raises(OAuth2Exception) as exc_info,
    ):
        example_provider.exchange_code("test_code", "https://example.com/callback")

    assert exc_info.value.error == "server_error"
    assert exc_info.value.error_description == "Token exchange failed: invalid_grant"
    assert len(caplog.records) == 1
    assert caplog.records[0].levelno == logging.ERROR
    assert caplog.records[0].getMessage() == "Token exchange failed: invalid_grant"


@respx.mock
def test_exchange_code_preserves_nonrecoverable_http_error_handling(
    example_provider: ExampleProvider,
    caplog: pytest.LogCaptureFixture,
) -> None:
    respx.post("https://example.com/login/oauth/access_token").mock(
        return_value=respx.MockResponse(
            400,
            json={
                "error": "invalid_grant",
                "error_description": "The grant is invalid.",
            },
        )
    )

    with (
        caplog.at_level(logging.WARNING, logger=logger.name),
        pytest.raises(OAuth2Exception) as exc_info,
    ):
        example_provider.exchange_code("test_code", "https://example.com/callback")

    assert exc_info.value.error == "server_error"
    assert exc_info.value.error_description == "Token exchange failed"
    assert len(caplog.records) == 1
    assert caplog.records[0].levelno == logging.WARNING
    assert (
        caplog.records[0]
        .getMessage()
        .startswith("HTTP error during token exchange: 400 - ")
    )


@pytest.fixture
def example_provider_with_pkce() -> ExampleProviderWithPKCE:
    return ExampleProviderWithPKCE(
        client_id="test_client_id", client_secret="test_client_secret"
    )


@respx.mock
def test_pkce_flow_includes_code_verifier(
    example_provider_with_pkce: ExampleProviderWithPKCE,
    context: Context,
) -> None:
    authorize_request = HTTPRequest(
        TestingHTTPRequestAdapter(
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

    authorize_response = start_token_flow(
        example_provider_with_pkce, authorize_request, context
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

    callback_request = HTTPRequest(
        TestingHTTPRequestAdapter(
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

    handle_callback(example_provider_with_pkce, callback_request, context)

    request_data = token_route.calls[0].request.content.decode()

    assert f"code_verifier={stored_verifier}" in request_data
