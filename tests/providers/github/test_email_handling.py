"""Tests for GitHub provider email handling.

These tests verify:
1. email_verified status is correctly extracted from GitHub's /user/emails response
2. noreply emails are filtered out
3. Fallback behavior when primary email is unavailable/filtered
"""

import pytest
import respx

from cross_auth.social_providers.github import GitHubProvider

pytestmark = pytest.mark.asyncio


# --- email_verified status tests ---


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
async def test_unverified_primary_with_verified_secondary(
    github_provider: GitHubProvider,
    mock_user_info: dict,
    mock_emails_unverified_primary: list[dict],
):
    """Primary email is unverified, secondary is verified → use secondary."""
    respx.get("https://api.github.com/user").mock(
        return_value=respx.MockResponse(200, json=mock_user_info)
    )
    respx.get("https://api.github.com/user/emails").mock(
        return_value=respx.MockResponse(200, json=mock_emails_unverified_primary)
    )

    user_info = github_provider.fetch_user_info("test_token")

    # Should fall back to verified non-primary email
    assert user_info["email"] == "octocat@example.com"
    assert user_info["email_verified"] is True


@respx.mock
async def test_all_emails_unverified(
    github_provider: GitHubProvider,
    mock_user_info: dict,
    mock_emails_all_unverified: list[dict],
):
    """All emails unverified → use primary, email_verified=False."""
    respx.get("https://api.github.com/user").mock(
        return_value=respx.MockResponse(200, json=mock_user_info)
    )
    respx.get("https://api.github.com/user/emails").mock(
        return_value=respx.MockResponse(200, json=mock_emails_all_unverified)
    )

    user_info = github_provider.fetch_user_info("test_token")

    assert user_info["email"] == "octocat@github.com"
    assert user_info["email_verified"] is False


# --- noreply filtering tests ---


@respx.mock
async def test_noreply_only_returns_no_email(
    github_provider: GitHubProvider,
    mock_user_info: dict,
    mock_emails_noreply_only: list[dict],
):
    """Only noreply email → email=None (filtered out)."""
    respx.get("https://api.github.com/user").mock(
        return_value=respx.MockResponse(200, json=mock_user_info)
    )
    respx.get("https://api.github.com/user/emails").mock(
        return_value=respx.MockResponse(200, json=mock_emails_noreply_only)
    )

    user_info = github_provider.fetch_user_info("test_token")

    assert user_info["email"] is None
    assert user_info["email_verified"] is None


@respx.mock
async def test_noreply_primary_with_verified_secondary(
    github_provider: GitHubProvider,
    mock_user_info: dict,
    mock_emails_noreply_and_verified: list[dict],
):
    """Noreply primary + verified secondary → use secondary."""
    respx.get("https://api.github.com/user").mock(
        return_value=respx.MockResponse(200, json=mock_user_info)
    )
    respx.get("https://api.github.com/user/emails").mock(
        return_value=respx.MockResponse(200, json=mock_emails_noreply_and_verified)
    )

    user_info = github_provider.fetch_user_info("test_token")

    assert user_info["email"] == "octocat@example.com"
    assert user_info["email_verified"] is True


@respx.mock
async def test_noreply_primary_with_unverified_secondary(
    github_provider: GitHubProvider,
    mock_user_info: dict,
    mock_emails_noreply_and_unverified: list[dict],
):
    """Noreply primary + unverified secondary → use secondary, unverified."""
    respx.get("https://api.github.com/user").mock(
        return_value=respx.MockResponse(200, json=mock_user_info)
    )
    respx.get("https://api.github.com/user/emails").mock(
        return_value=respx.MockResponse(200, json=mock_emails_noreply_and_unverified)
    )

    user_info = github_provider.fetch_user_info("test_token")

    assert user_info["email"] == "octocat@example.com"
    assert user_info["email_verified"] is False


# --- edge cases ---


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
