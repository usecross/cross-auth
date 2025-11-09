import pytest

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
