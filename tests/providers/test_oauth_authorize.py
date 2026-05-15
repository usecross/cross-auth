import pytest
from cross_web import HTTPRequest, TestingHTTPRequestAdapter

from cross_auth._auth_flow import AuthRequest, start_token_flow
from cross_auth._context import Context
from cross_auth._storage import SecondaryStorage
from cross_auth.social_providers.oauth import OAuth2Provider


@pytest.mark.parametrize(
    "query_params",
    [
        {},
        {"response_type": "invalid"},
    ],
)
def test_invalid_request_when_response_type_is_missing_or_invalid(
    oauth_provider: OAuth2Provider, context: Context, query_params: dict
):
    request = HTTPRequest(
        TestingHTTPRequestAdapter(
            method="GET",
            url="http://localhost:8000/test/authorize",
            query_params={
                "client_id": "test_client_id",
                "redirect_uri": "http://valid-frontend.com/callback",
                **query_params,
            },
        )
    )

    response = start_token_flow(oauth_provider, request, context)

    assert response.status_code == 302
    assert response.headers is not None
    assert "Location" in response.headers
    assert "error=invalid_request" in response.headers["Location"]


def test_authorize_redirects_to_provider(
    oauth_provider: OAuth2Provider,
    context: Context,
    secondary_storage: SecondaryStorage,
):
    request = HTTPRequest(
        TestingHTTPRequestAdapter(
            method="GET",
            url="http://localhost:8000/test/authorize",
            query_params={
                "client_id": "my_app_client_id",
                "redirect_uri": "http://valid-frontend.com/callback",
                "state": "test_state",
                "response_type": "code",
                "code_challenge": "test",
                "code_challenge_method": "S256",
            },
        )
    )

    response = start_token_flow(oauth_provider, request, context)

    assert response.status_code == 302
    assert response.headers is not None
    assert "Location" in response.headers

    location = response.headers["Location"]
    assert location.startswith(oauth_provider.authorization_endpoint)
    # The provider's client_id is sent to the external provider, not the app's client_id
    assert "client_id=test_client_id" in location
    assert "scope=openid+email+profile" in location
    assert "redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Ftest%2Fcallback" in location

    state = location.split("state=")[1].split("&")[0]

    raw_authorization_request_data = secondary_storage.get(
        f"oauth:authorization_request:{state}"
    )

    assert raw_authorization_request_data is not None

    authorization_request_data = AuthRequest.model_validate_json(
        raw_authorization_request_data
    )

    # The app's client_id is stored in the authorization request data
    assert authorization_request_data.flow == "token"
    assert authorization_request_data.client_id == "my_app_client_id"
    assert (
        authorization_request_data.client_redirect_uri
        == "http://valid-frontend.com/callback"
    )
    assert authorization_request_data.state == state
    assert authorization_request_data.client_code_challenge == "test"
    assert authorization_request_data.client_code_challenge_method == "S256"


def test_authorize_requires_redirect_uri(
    oauth_provider: OAuth2Provider, context: Context
):
    request = HTTPRequest(
        TestingHTTPRequestAdapter(
            method="GET", url="http://localhost:8000/test/authorize", query_params={}
        )
    )

    response = start_token_flow(oauth_provider, request, context)

    assert response.status_code == 400
    assert response.json() == {"error": "invalid_request"}


def test_invalid_redirect_uri_error(oauth_provider: OAuth2Provider, context: Context):
    request = HTTPRequest(
        TestingHTTPRequestAdapter(
            method="GET",
            url="http://localhost:8000/test/authorize",
            query_params={
                "client_id": "test_client_id",
                "redirect_uri": "http://malicious.com/callback",  # Unregistered redirect URI
                "response_type": "code",
            },
        )
    )

    response = start_token_flow(oauth_provider, request, context)

    assert response.status_code == 400
    assert response.json() == {"error": "invalid_redirect_uri"}


def test_link_code_response_type_not_supported(
    oauth_provider: OAuth2Provider, context: Context
):
    """
    The authorize endpoint no longer supports response_type=link_code.
    Use POST /{provider}/link instead.
    """
    request = HTTPRequest(
        TestingHTTPRequestAdapter(
            method="GET",
            url="http://localhost:8000/test/authorize",
            query_params={
                "client_id": "my_app_client_id",
                "redirect_uri": "http://valid-frontend.com/callback",
                "state": "client_state_123",
                "response_type": "link_code",
                "code_challenge": "test_challenge",
                "code_challenge_method": "S256",
            },
            headers={"Authorization": "Bearer test"},
        )
    )

    response = start_token_flow(oauth_provider, request, context)

    assert response.status_code == 302
    assert response.headers is not None
    location = response.headers["Location"]
    assert "error=invalid_request" in location
    assert "state=client_state_123" in location


def test_authorize_rejects_invalid_client_id(
    oauth_provider: OAuth2Provider,
    secondary_storage: SecondaryStorage,
    accounts_storage,
    logged_in_user,
):
    """When allowed_client_ids is configured, reject unknown client_ids."""
    context_with_client_validation = Context(
        secondary_storage=secondary_storage,
        accounts_storage=accounts_storage,
        create_token=lambda id: (f"token-{id}", 0),
        get_user_from_request=lambda r: (
            logged_in_user if r.headers.get("Authorization") == "Bearer test" else None
        ),
        trusted_origins=["valid-frontend.com"],
        config={"allowed_client_ids": ["allowed_client"]},
    )

    request = HTTPRequest(
        TestingHTTPRequestAdapter(
            method="GET",
            url="http://localhost:8000/test/authorize",
            query_params={
                "client_id": "unknown_client",
                "redirect_uri": "http://valid-frontend.com/callback",
                "state": "test_state",
                "response_type": "code",
                "code_challenge": "test",
                "code_challenge_method": "S256",
            },
        )
    )

    response = start_token_flow(oauth_provider, request, context_with_client_validation)

    assert response.status_code == 302
    assert response.headers is not None
    location = response.headers["Location"]
    assert "error=invalid_client" in location
    assert "error_description=Invalid+client_id" in location


def test_authorize_accepts_valid_client_id(
    oauth_provider: OAuth2Provider,
    secondary_storage: SecondaryStorage,
    accounts_storage,
    logged_in_user,
):
    """When allowed_client_ids is configured, accept known client_ids."""
    context_with_client_validation = Context(
        secondary_storage=secondary_storage,
        accounts_storage=accounts_storage,
        create_token=lambda id: (f"token-{id}", 0),
        get_user_from_request=lambda r: (
            logged_in_user if r.headers.get("Authorization") == "Bearer test" else None
        ),
        trusted_origins=["valid-frontend.com"],
        config={"allowed_client_ids": ["allowed_client"]},
    )

    request = HTTPRequest(
        TestingHTTPRequestAdapter(
            method="GET",
            url="http://localhost:8000/test/authorize",
            query_params={
                "client_id": "allowed_client",
                "redirect_uri": "http://valid-frontend.com/callback",
                "state": "test_state",
                "response_type": "code",
                "code_challenge": "test",
                "code_challenge_method": "S256",
            },
        )
    )

    response = start_token_flow(oauth_provider, request, context_with_client_validation)

    assert response.status_code == 302
    assert response.headers is not None
    location = response.headers["Location"]
    # Should redirect to provider, not error
    assert location.startswith(oauth_provider.authorization_endpoint)
