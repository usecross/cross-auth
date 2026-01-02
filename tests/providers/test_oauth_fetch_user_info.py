"""Tests for OAuth2Provider.fetch_user_info() method."""

import pytest
import respx

from cross_auth.social_providers.oauth import OAuth2Exception

from .conftest import TestOAuth2Provider

pytestmark = pytest.mark.asyncio


@respx.mock
async def test_fetch_user_info_success(oauth_provider: TestOAuth2Provider):
    """Successfully fetches user info."""
    respx.get("https://test.com/userinfo").mock(
        return_value=respx.MockResponse(
            200, json={"id": "123", "email": "test@example.com"}
        )
    )

    user_info = oauth_provider.fetch_user_info("test_token")

    assert user_info["id"] == "123"
    assert user_info["email"] == "test@example.com"


@respx.mock
async def test_fetch_user_info_endpoint_fails(oauth_provider: TestOAuth2Provider):
    """User info endpoint returning error raises OAuth2Exception."""
    respx.get("https://test.com/userinfo").mock(
        return_value=respx.MockResponse(401, json={"error": "invalid_token"})
    )

    with pytest.raises(OAuth2Exception) as exc_info:
        oauth_provider.fetch_user_info("test_token")

    assert exc_info.value.error == "server_error"
    assert exc_info.value.error_description == "Failed to fetch user info"
