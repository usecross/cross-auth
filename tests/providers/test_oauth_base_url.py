import pytest
from lia import AsyncHTTPRequest
from lia.request import TestingRequestAdapter

from cross_auth._context import Context
from cross_auth._storage import SecondaryStorage
from cross_auth.social_providers.oauth import (
    OAuth2Provider,
)

pytestmark = pytest.mark.asyncio


@pytest.fixture
def context_with_base_url(
    secondary_storage: SecondaryStorage,
    accounts_storage,
    logged_in_user,
) -> Context:
    def _get_user_from_request(request: AsyncHTTPRequest):
        if request.headers.get("Authorization") == "Bearer test":
            return logged_in_user
        return None

    return Context(
        secondary_storage=secondary_storage,
        accounts_storage=accounts_storage,
        create_token=lambda id: (f"token-{id}", 0),
        get_user_from_request=_get_user_from_request,
        trusted_origins=["valid-frontend.com"],
        base_url="http://localhost:8000",
    )


async def test_authorize_uses_base_url_for_redirect_uri(
    oauth_provider: OAuth2Provider,
    context_with_base_url: Context,
    secondary_storage: SecondaryStorage,
):
    """Test that when base_url is configured, it's used for the OAuth redirect URI instead of the request URL."""
    # Simulate a request from Docker container with internal hostname
    request = AsyncHTTPRequest(
        TestingRequestAdapter(
            method="GET",
            url="http://backend:8000/auth/github/authorize",
            query_params={
                "redirect_uri": "http://valid-frontend.com/callback",
                "state": "test_state",
                "response_type": "code",
                "code_challenge": "test",
                "code_challenge_method": "S256",
            },
        )
    )

    response = await oauth_provider.authorize(request, context_with_base_url)

    assert response.status_code == 302
    assert response.headers is not None
    assert "Location" in response.headers

    location = response.headers["Location"]
    assert location.startswith(oauth_provider.authorization_endpoint)

    # The redirect_uri should use localhost:8000, not backend:8000
    assert (
        "redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Fauth%2Fgithub%2Fcallback"
        in location
    )
    # Should NOT contain the internal Docker hostname
    assert "backend" not in location


async def test_authorize_with_nested_path_and_base_url(
    oauth_provider: OAuth2Provider,
    context_with_base_url: Context,
    secondary_storage: SecondaryStorage,
):
    """Test that nested paths are handled correctly with base_url."""
    request = AsyncHTTPRequest(
        TestingRequestAdapter(
            method="GET",
            url="http://backend:8000/api/v1/auth/github/authorize",
            query_params={
                "redirect_uri": "http://valid-frontend.com/callback",
                "state": "test_state",
                "response_type": "code",
                "code_challenge": "test",
                "code_challenge_method": "S256",
            },
        )
    )

    response = await oauth_provider.authorize(request, context_with_base_url)

    assert response.status_code == 302
    assert response.headers is not None
    location = response.headers["Location"]

    # Should preserve the full path structure
    assert (
        "redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Fapi%2Fv1%2Fauth%2Fgithub%2Fcallback"
        in location
    )


async def test_authorize_without_base_url_fallback(
    oauth_provider: OAuth2Provider,
    context: Context,  # This fixture doesn't have base_url
    secondary_storage: SecondaryStorage,
):
    """Test that without base_url, the request URL is used as before."""
    request = AsyncHTTPRequest(
        TestingRequestAdapter(
            method="GET",
            url="http://backend:8000/test/authorize",
            query_params={
                "redirect_uri": "http://valid-frontend.com/callback",
                "state": "test_state",
                "response_type": "code",
                "code_challenge": "test",
                "code_challenge_method": "S256",
            },
        )
    )

    response = await oauth_provider.authorize(request, context)

    assert response.status_code == 302
    assert response.headers is not None
    location = response.headers["Location"]

    # Without base_url, should use the request URL
    assert "redirect_uri=http%3A%2F%2Fbackend%3A8000%2Ftest%2Fcallback" in location


async def test_authorize_base_url_with_trailing_slash(
    oauth_provider: OAuth2Provider,
    secondary_storage: SecondaryStorage,
    accounts_storage,
    logged_in_user,
):
    """Test that base_url with trailing slash is handled correctly."""
    # Create context with trailing slash in base_url
    context = Context(
        secondary_storage=secondary_storage,
        accounts_storage=accounts_storage,
        create_token=lambda id: (f"token-{id}", 0),
        get_user_from_request=lambda r: logged_in_user
        if r.headers.get("Authorization") == "Bearer test"
        else None,
        trusted_origins=["valid-frontend.com"],
        base_url="http://localhost:8000/",  # Trailing slash
    )

    request = AsyncHTTPRequest(
        TestingRequestAdapter(
            method="GET",
            url="http://backend:8000/auth/authorize",
            query_params={
                "redirect_uri": "http://valid-frontend.com/callback",
                "state": "test_state",
                "response_type": "code",
                "code_challenge": "test",
                "code_challenge_method": "S256",
            },
        )
    )

    response = await oauth_provider.authorize(request, context)

    assert response.status_code == 302
    assert response.headers is not None
    location = response.headers["Location"]

    # Should handle trailing slash correctly and not create double slashes
    assert "redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Fauth%2Fcallback" in location
    # Check that there are no double slashes in the path part (after the protocol)
    # Note: %2F%2F is expected in http:// but not in the path
    import urllib.parse

    redirect_uri_match = location.split("redirect_uri=")[1].split("&")[0]
    decoded_uri = urllib.parse.unquote(redirect_uri_match)
    assert "//" not in decoded_uri.replace("http://", "").replace("https://", "")


async def test_authorize_base_url_with_different_port(
    oauth_provider: OAuth2Provider,
    secondary_storage: SecondaryStorage,
    accounts_storage,
    logged_in_user,
):
    """Test base_url with a different port number."""
    context = Context(
        secondary_storage=secondary_storage,
        accounts_storage=accounts_storage,
        create_token=lambda id: (f"token-{id}", 0),
        get_user_from_request=lambda r: logged_in_user
        if r.headers.get("Authorization") == "Bearer test"
        else None,
        trusted_origins=["valid-frontend.com"],
        base_url="https://api.example.com:9000",
    )

    request = AsyncHTTPRequest(
        TestingRequestAdapter(
            method="GET",
            url="http://internal-service:8080/auth/provider/authorize",
            query_params={
                "redirect_uri": "http://valid-frontend.com/callback",
                "state": "test_state",
                "response_type": "code",
                "code_challenge": "test",
                "code_challenge_method": "S256",
            },
        )
    )

    response = await oauth_provider.authorize(request, context)

    assert response.status_code == 302
    assert response.headers is not None
    location = response.headers["Location"]

    # Should use the configured base_url with its port
    assert (
        "redirect_uri=https%3A%2F%2Fapi.example.com%3A9000%2Fauth%2Fprovider%2Fcallback"
        in location
    )
