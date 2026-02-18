"""Tests for GitHubProvider.fetch_user_info() method."""

from typing import Any, cast

import pytest
import respx

from cross_auth.social_providers.github import GitHubProvider
from cross_auth.social_providers.oauth import OAuth2Exception

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

    user_info = cast(dict[str, Any], github_provider.fetch_user_info("test_token"))

    assert user_info["id"] == 1
    assert user_info["login"] == "octocat"
    assert user_info["email"] == "octocat@github.com"


@respx.mock
async def test_fetch_user_info_without_email_in_profile(
    github_provider: GitHubProvider, mock_user_info: dict, mock_emails: list[dict]
):
    """Email not in /user response -> still resolved from /user/emails."""
    mock_user_info.pop("email", None)

    respx.get("https://api.github.com/user").mock(
        return_value=respx.MockResponse(200, json=mock_user_info)
    )
    respx.get("https://api.github.com/user/emails").mock(
        return_value=respx.MockResponse(200, json=mock_emails)
    )

    user_info = github_provider.fetch_user_info("test_token")

    assert user_info["email"] == "octocat@github.com"
    assert user_info["email_verified"] is True


@respx.mock
async def test_name_fallback_to_login(
    github_provider: GitHubProvider,
    mock_user_info: dict,
    mock_emails_verified_primary: list[dict],
):
    """User with no name -> fallback to login."""
    mock_user_info["name"] = None

    respx.get("https://api.github.com/user").mock(
        return_value=respx.MockResponse(200, json=mock_user_info)
    )
    respx.get("https://api.github.com/user/emails").mock(
        return_value=respx.MockResponse(200, json=mock_emails_verified_primary)
    )

    user_info = cast(dict[str, Any], github_provider.fetch_user_info("test_token"))

    assert user_info["name"] == "octocat"


@respx.mock
async def test_emails_stashed_in_user_info(
    github_provider: GitHubProvider, mock_user_info: dict, mock_emails: list[dict]
):
    """Emails should be stashed in user_info dict for resolve_email."""
    respx.get("https://api.github.com/user").mock(
        return_value=respx.MockResponse(200, json=mock_user_info)
    )
    respx.get("https://api.github.com/user/emails").mock(
        return_value=respx.MockResponse(200, json=mock_emails)
    )

    user_info = cast(dict[str, Any], github_provider.fetch_user_info("test_token"))

    assert "_github_emails" in user_info
    assert len(user_info["_github_emails"]) == 2


@respx.mock
async def test_email_fetch_error_raises(
    github_provider: GitHubProvider, mock_user_info: dict
):
    """Emails endpoint fails -> raises OAuth2Exception."""
    mock_user_info.pop("email", None)

    respx.get("https://api.github.com/user").mock(
        return_value=respx.MockResponse(200, json=mock_user_info)
    )
    respx.get("https://api.github.com/user/emails").mock(
        return_value=respx.MockResponse(500, json={"message": "Internal Server Error"})
    )

    with pytest.raises(OAuth2Exception) as exc:
        github_provider.fetch_user_info("test_token")

    assert "Failed to fetch user emails" in exc.value.error_description


@respx.mock
async def test_user_info_endpoint_error_raises(github_provider: GitHubProvider):
    """User info endpoint fails -> raises OAuth2Exception."""
    respx.get("https://api.github.com/user").mock(
        return_value=respx.MockResponse(500, json={"message": "Internal Server Error"})
    )

    with pytest.raises(OAuth2Exception) as exc:
        github_provider.fetch_user_info("test_token")

    assert "Failed to fetch user info" in exc.value.error_description
