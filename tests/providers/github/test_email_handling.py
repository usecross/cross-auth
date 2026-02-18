"""Tests for how fetch_user_info handles different email states."""

import pytest
import respx

from cross_auth.social_providers.github import GitHubProvider

pytestmark = pytest.mark.asyncio


@respx.mock
async def test_unverified_primary_email(
    github_provider: GitHubProvider,
    mock_user_info: dict,
    mock_emails_unverified_primary: list[dict],
):
    """Primary email is unverified -> email_verified=False."""
    respx.get("https://api.github.com/user").mock(
        return_value=respx.MockResponse(200, json=mock_user_info)
    )
    respx.get("https://api.github.com/user/emails").mock(
        return_value=respx.MockResponse(200, json=mock_emails_unverified_primary)
    )

    user_info = github_provider.fetch_user_info("test_token")

    assert user_info["email"] == "octocat@github.com"
    assert user_info["email_verified"] is False


@respx.mock
async def test_empty_emails_list(
    github_provider: GitHubProvider,
    mock_user_info: dict,
    mock_emails_empty: list[dict],
):
    """No emails returned -> email=None."""
    respx.get("https://api.github.com/user").mock(
        return_value=respx.MockResponse(200, json=mock_user_info)
    )
    respx.get("https://api.github.com/user/emails").mock(
        return_value=respx.MockResponse(200, json=mock_emails_empty)
    )

    user_info = github_provider.fetch_user_info("test_token")

    assert user_info["email"] is None
    assert user_info["email_verified"] is None
