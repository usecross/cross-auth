"""Tests for GitHubProvider.fetch_user_info() method."""

import pytest
import respx

from cross_auth.social_providers.github import GitHubProvider

pytestmark = pytest.mark.asyncio


@respx.mock
async def test_fetch_user_info_success(
    github_provider: GitHubProvider,
    mock_user_info: dict,
    mock_emails_verified_primary: list[dict],
):
    """Successfully fetches user info and emails."""
    respx.get("https://api.github.com/user").mock(
        return_value=respx.MockResponse(200, json=mock_user_info)
    )
    respx.get("https://api.github.com/user/emails").mock(
        return_value=respx.MockResponse(200, json=mock_emails_verified_primary)
    )

    user_info = github_provider.fetch_user_info("test_token")

    assert user_info["id"] == 1
    assert user_info["login"] == "octocat"
    assert user_info["email"] == "octocat@github.com"


# TODO: test_fetch_user_info_user_endpoint_fails should be in base OAuth2Provider tests
# The base class currently doesn't check HTTP status codes (bug)


@respx.mock
async def test_name_fallback_to_login(
    github_provider: GitHubProvider,
    mock_user_info: dict,
    mock_emails_verified_primary: list[dict],
):
    """User with no name → fallback to login."""
    mock_user_info["name"] = None

    respx.get("https://api.github.com/user").mock(
        return_value=respx.MockResponse(200, json=mock_user_info)
    )
    respx.get("https://api.github.com/user/emails").mock(
        return_value=respx.MockResponse(200, json=mock_emails_verified_primary)
    )

    user_info = github_provider.fetch_user_info("test_token")

    assert user_info["name"] == "octocat"
