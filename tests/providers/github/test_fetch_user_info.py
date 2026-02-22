"""Tests for GitHubProvider.get_user_info() method."""

from typing import Any, cast
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
async def test_get_user_info_success(
    github_provider: GitHubProvider,
    mock_user_info: dict,
    mock_emails_verified_primary: list[dict],
    token_response: TokenResponse,
    context: MagicMock,
):
    """Successfully fetches user info and emails."""
    respx.get("https://api.github.com/user").mock(
        return_value=respx.MockResponse(200, json=mock_user_info)
    )
    respx.get("https://api.github.com/user/emails").mock(
        return_value=respx.MockResponse(200, json=mock_emails_verified_primary)
    )

    user_info = cast(
        dict[str, Any], github_provider.get_user_info(token_response, context)
    )

    assert user_info["id"] == 1
    assert user_info["login"] == "octocat"
    assert user_info["email"] == "octocat@github.com"


@respx.mock
async def test_name_fallback_to_login(
    github_provider: GitHubProvider,
    mock_user_info: dict,
    mock_emails_verified_primary: list[dict],
    token_response: TokenResponse,
    context: MagicMock,
):
    """User with no name -> fallback to login."""
    mock_user_info["name"] = None

    respx.get("https://api.github.com/user").mock(
        return_value=respx.MockResponse(200, json=mock_user_info)
    )
    respx.get("https://api.github.com/user/emails").mock(
        return_value=respx.MockResponse(200, json=mock_emails_verified_primary)
    )

    user_info = cast(
        dict[str, Any], github_provider.get_user_info(token_response, context)
    )

    assert user_info["name"] == "octocat"
