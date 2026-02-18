"""Tests for GitHubProvider email selection."""

import pytest

from cross_auth.social_providers.github import GitHubProvider
from cross_auth.social_providers.github.provider import Email
from cross_auth.social_providers.oauth import (
    NoEmailError,
    NoVerifiedEmailError,
    OAuth2Exception,
)


def test_signup_uses_primary_verified_email():
    provider = GitHubProvider(client_id="id", client_secret="secret")
    emails = [
        Email(email="primary@example.com", primary=True, verified=True),
        Email(email="other@example.com", primary=False, verified=True),
    ]
    result = provider._select_email(emails, is_login=False)

    assert result == "primary@example.com"


def test_signup_falls_back_when_primary_unverified():
    provider = GitHubProvider(client_id="id", client_secret="secret")

    emails = [
        Email(email="primary@example.com", primary=True, verified=False),
        Email(email="other@example.com", primary=False, verified=True),
    ]
    result = provider._select_email(emails, is_login=False)

    assert result == "other@example.com"


def test_signup_blocks_noreply_emails_by_default():
    provider = GitHubProvider(client_id="id", client_secret="secret")
    emails = [
        Email(email="123+user@users.noreply.github.com", primary=True, verified=True),
    ]
    with pytest.raises(NoVerifiedEmailError):
        provider._select_email(emails, is_login=False)


def test_signup_allows_noreply_when_configured():
    provider = GitHubProvider(
        client_id="id", client_secret="secret", allow_noreply_emails=True
    )
    emails = [
        Email(email="123+user@users.noreply.github.com", primary=True, verified=True),
    ]
    result = provider._select_email(emails, is_login=False)
    assert result == "123+user@users.noreply.github.com"


def test_signup_blocks_ghe_noreply_emails():
    """GHE noreply emails should be filtered when api_base_url is set."""
    provider = GitHubProvider(
        client_id="id",
        client_secret="secret",
        api_base_url="https://github.example.com/api/v3",
    )
    emails = [
        Email(
            email="123+user@users.noreply.github.example.com",
            primary=True,
            verified=True,
        ),
    ]
    with pytest.raises(NoVerifiedEmailError):
        provider._select_email(emails, is_login=False)


def test_login_accepts_any_verified_email_by_default():
    provider = GitHubProvider(client_id="id", client_secret="secret")
    emails = [
        Email(email="new@example.com", primary=True, verified=True),
    ]
    result = provider._select_email(
        emails, is_login=True, stored_email="old@example.com"
    )
    assert result == "new@example.com"


def test_login_prefers_stored_email_if_still_verified():
    provider = GitHubProvider(client_id="id", client_secret="secret")
    emails = [
        Email(email="new@example.com", primary=True, verified=True),
        Email(email="stored@example.com", primary=False, verified=True),
    ]
    result = provider._select_email(
        emails, is_login=True, stored_email="stored@example.com"
    )
    assert result == "stored@example.com"


def test_login_matches_stored_email_case_insensitively():
    """Stored email should match even when local part differs in case."""
    provider = GitHubProvider(client_id="id", client_secret="secret")
    emails = [
        Email(email="new@example.com", primary=True, verified=True),
        # EmailStr normalizes domain; local part casing is preserved
        Email(email="Stored@example.com", primary=False, verified=True),
    ]
    result = provider._select_email(
        emails, is_login=True, stored_email="stored@example.com"
    )
    assert result == "Stored@example.com"


def test_login_blocks_noreply_by_default():
    provider = GitHubProvider(client_id="id", client_secret="secret")
    emails = [
        Email(email="123+user@users.noreply.github.com", primary=True, verified=True),
    ]
    with pytest.raises(NoVerifiedEmailError):
        provider._select_email(emails, is_login=True)


def test_resolve_email_uses_stashed_emails():
    provider = GitHubProvider(client_id="id", client_secret="secret")
    user_info: dict = {
        "id": 123,
        "email": "ignored@example.com",
        "_github_emails": [
            Email(email="test@example.com", primary=True, verified=True),
        ],
    }

    result = provider.resolve_email(user_info, is_login=False)

    assert result.email == "test@example.com"
    assert result.email_verified is True
    assert "_github_emails" not in user_info  # Should be consumed


def test_resolve_email_requires_stashed_emails():
    provider = GitHubProvider(client_id="id", client_secret="secret")
    user_info: dict = {"id": 123}

    with pytest.raises(OAuth2Exception):
        provider.resolve_email(user_info, is_login=False)


def test_resolve_email_raises_when_no_emails():
    provider = GitHubProvider(client_id="id", client_secret="secret")
    user_info: dict = {"id": 123, "_github_emails": []}

    with pytest.raises(NoEmailError):
        provider.resolve_email(user_info, is_login=False)
