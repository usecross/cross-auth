from unittest.mock import MagicMock

import pytest
import respx

from cross_auth.models.oauth_token_response import TokenResponse
from cross_auth.social_providers.github import GitHubProvider

pytestmark = pytest.mark.asyncio


@pytest.fixture
def token_response() -> TokenResponse:
    return TokenResponse(
        token_type="Bearer",
        access_token="test_token",
    )


@pytest.fixture
def context() -> MagicMock:
    return MagicMock()


@respx.mock
async def test_verified_primary_email(
    github_provider: GitHubProvider,
    mock_user_info: dict[str, str],
    mock_emails_verified_primary: list[dict[str, str]],
    token_response: TokenResponse,
    context: MagicMock,
):
    """Primary email is verified -> email_verified=True."""
    respx.get("https://api.github.com/user").mock(
        return_value=respx.MockResponse(200, json=mock_user_info)
    )
    respx.get("https://api.github.com/user/emails").mock(
        return_value=respx.MockResponse(200, json=mock_emails_verified_primary)
    )

    user_info = github_provider.get_user_info(token_response, context)

    assert user_info["email"] == "octocat@github.com"
    assert user_info["email_verified"] is True


@respx.mock
async def test_unverified_primary_email(
    github_provider: GitHubProvider,
    mock_user_info: dict[str, str],
    mock_emails_unverified_primary: list[dict[str, str]],
    token_response: TokenResponse,
    context: MagicMock,
):
    """Primary email is unverified -> email_verified=False."""
    respx.get("https://api.github.com/user").mock(
        return_value=respx.MockResponse(200, json=mock_user_info)
    )
    respx.get("https://api.github.com/user/emails").mock(
        return_value=respx.MockResponse(200, json=mock_emails_unverified_primary)
    )

    user_info = github_provider.get_user_info(token_response, context)

    assert user_info["email"] == "octocat@github.com"
    assert user_info["email_verified"] is False


@respx.mock
async def test_empty_emails_list(
    github_provider: GitHubProvider,
    mock_user_info: dict[str, str],
    mock_emails_empty: list[dict[str, str]],
    token_response: TokenResponse,
    context: MagicMock,
):
    """No emails returned -> email=None."""
    respx.get("https://api.github.com/user").mock(
        return_value=respx.MockResponse(200, json=mock_user_info)
    )
    respx.get("https://api.github.com/user/emails").mock(
        return_value=respx.MockResponse(200, json=mock_emails_empty)
    )

    user_info = github_provider.get_user_info(token_response, context)

    assert user_info["email"] is None
    assert user_info["email_verified"] is None


@respx.mock
async def test_emails_endpoint_fails_gracefully(
    github_provider: GitHubProvider,
    mock_user_info: dict[str, str],
    token_response: TokenResponse,
    context: MagicMock,
):
    """Emails endpoint fails -> email=None (graceful degradation)."""
    respx.get("https://api.github.com/user").mock(
        return_value=respx.MockResponse(200, json=mock_user_info)
    )
    respx.get("https://api.github.com/user/emails").mock(
        return_value=respx.MockResponse(500, json={"message": "Internal Server Error"})
    )

    user_info = github_provider.get_user_info(token_response, context)

    assert user_info["email"] is None
    assert user_info["email_verified"] is None
