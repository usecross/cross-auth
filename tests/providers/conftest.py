import pytest
from cross_web import AsyncHTTPRequest

from cross_auth._completion import AuthCompletion
from cross_auth._context import Context
from cross_auth._provider_service import parse_callback_and_load_state
from cross_auth.models.oauth_token_response import TokenResponse
from cross_auth.social_providers.oauth import OAuth2Exception, OAuth2Provider
from cross_auth.utils._response import Response

pytestmark = pytest.mark.asyncio


class TestOAuth2Provider(OAuth2Provider):
    __test__ = False
    id = "test"
    authorization_endpoint = "https://test.com/authorize"
    token_endpoint = "https://test.com/token"
    user_info_endpoint = "https://test.com/userinfo"
    scopes = ["openid", "email", "profile"]
    supports_pkce = True


@pytest.fixture(autouse=True)
def _deterministic_codes(monkeypatch):
    """Completions generate local codes via uuid.uuid4(); pin it for snapshot stability."""
    import uuid

    class _FakeUUID:
        def __str__(self) -> str:
            return "a-totally-valid-code"

    monkeypatch.setattr(uuid, "uuid4", lambda: _FakeUUID())


@pytest.fixture
def oauth_provider() -> TestOAuth2Provider:
    return TestOAuth2Provider(
        client_id="test_client_id", client_secret="test_client_secret"
    )


@pytest.fixture
def token_response() -> TokenResponse:
    return TokenResponse(
        token_type="Bearer",
        access_token="test_token",
    )


async def dispatch_callback(
    provider: OAuth2Provider,
    request: AsyncHTTPRequest,
    context: Context,
    completion: AuthCompletion,
) -> Response:
    """Simulates the router's /{provider}/callback dispatch for a single completion.

    Mirrors router._make_callback_handler so provider-level tests can exercise
    the full callback pipeline (parse + dispatch + complete/on_failure) without
    spinning up a full router.
    """
    try:
        callback_data, flow_state = await parse_callback_and_load_state(
            provider, request, context
        )
    except OAuth2Exception as e:
        return Response.error(e.error, error_description=e.error_description)

    if not callback_data.code:
        error = OAuth2Exception(
            error="server_error",
            error_description="No authorization code received in callback",
        )
        return await completion.on_failure(request, context, error, flow_state)

    try:
        return await completion.complete(
            request,
            context,
            provider,
            callback_data.code,
            callback_data.extra,
            flow_state,
        )
    except OAuth2Exception as e:
        return await completion.on_failure(request, context, e, flow_state)
