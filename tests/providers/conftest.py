import json

import pytest
from cross_web import AsyncHTTPRequest, TestingRequestAdapter

from cross_auth._context import SecondaryStorage
from cross_auth.social_providers.oauth import OAuth2Provider

pytestmark = pytest.mark.asyncio


class TestOAuth2Provider(OAuth2Provider):
    __test__ = False
    id = "test"
    authorization_endpoint = "https://test.com/authorize"
    token_endpoint = "https://test.com/token"
    user_info_endpoint = "https://test.com/userinfo"
    scopes = ["openid", "email", "profile"]
    supports_pkce = True

    def _generate_code(self) -> str:
        return "a-totally-valid-code"


@pytest.fixture
def oauth_provider() -> TestOAuth2Provider:
    return TestOAuth2Provider(
        client_id="test_client_id", client_secret="test_client_secret"
    )


@pytest.fixture
def valid_callback_request(secondary_storage: SecondaryStorage) -> AsyncHTTPRequest:
    secondary_storage.set(
        "oauth:authorization_request:test_state",
        json.dumps(
            {
                "client_id": "my_app_client_id",
                "redirect_uri": "http://valid-frontend.com/callback",
                "login_hint": "test_login_hint",
                "state": "test_state",
                "client_state": "test_client_state",
                "code_challenge": "test",
                "code_challenge_method": "S256",
                "provider_code_verifier": "test_provider_verifier",
            }
        ),
    )

    return AsyncHTTPRequest(
        TestingRequestAdapter(
            method="GET",
            url="http://localhost:8000/test/callback",
            query_params={
                "code": "test_code",
                "state": "test_state",
            },
        )
    )
