"""Tests for GitHub provider email handling.

These tests verify that the primary email is always used with its verification status.
"""

import pytest
import respx

from cross_auth.social_providers.github import GitHubProvider

pytestmark = pytest.mark.asyncio


@respx.mock
async def test_verified_primary_email(
    github_provider: GitHubProvider,
    mock_user_info: dict,
    mock_emails_verified_primary: list[dict],
):
    """Primary email is verified → email_verified=True."""
    respx.get("https://api.github.com/user").mock(
        return_value=respx.MockResponse(200, json=mock_user_info)
    )
    respx.get("https://api.github.com/user/emails").mock(
        return_value=respx.MockResponse(200, json=mock_emails_verified_primary)
    )

    user_info = github_provider.fetch_user_info("test_token")

    assert user_info["email"] == "octocat@github.com"
    assert user_info["email_verified"] is True


@respx.mock
async def test_unverified_primary_email(
    github_provider: GitHubProvider,
    mock_user_info: dict,
    mock_emails_unverified_primary: list[dict],
):
    """Primary email is unverified → email_verified=False."""
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
    """No emails returned → email=None."""
    respx.get("https://api.github.com/user").mock(
        return_value=respx.MockResponse(200, json=mock_user_info)
    )
    respx.get("https://api.github.com/user/emails").mock(
        return_value=respx.MockResponse(200, json=mock_emails_empty)
    )

    user_info = github_provider.fetch_user_info("test_token")

    assert user_info["email"] is None
    assert user_info["email_verified"] is None


@respx.mock
async def test_emails_endpoint_fails_gracefully(
    github_provider: GitHubProvider,
    mock_user_info: dict,
):
    """Emails endpoint fails → email=None (graceful degradation)."""
    respx.get("https://api.github.com/user").mock(
        return_value=respx.MockResponse(200, json=mock_user_info)
    )
    respx.get("https://api.github.com/user/emails").mock(
        return_value=respx.MockResponse(500, json={"message": "Internal Server Error"})
    )

    user_info = github_provider.fetch_user_info("test_token")

    assert user_info["email"] is None
    assert user_info["email_verified"] is None
