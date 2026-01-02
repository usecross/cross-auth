import datetime
import json

import httpx
import pytest
import time_machine
from inline_snapshot import snapshot
from lia import AsyncHTTPRequest
from lia.request import TestingRequestAdapter
from respx import MockRouter

from cross_auth._context import Context, SecondaryStorage
from cross_auth._issuer import AuthorizationCodeGrantData
from cross_auth.social_providers.oauth import OAuth2Provider

from ..conftest import MemoryAccountsStorage

pytestmark = pytest.mark.asyncio


@pytest.fixture
def valid_callback_request(secondary_storage: SecondaryStorage) -> AsyncHTTPRequest:
    secondary_storage.set(
        "oauth:authorization_request:test_state",
        json.dumps(
            {
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


async def test_fails_if_there_were_no_provider_data_in_secondary_storage(
    oauth_provider: OAuth2Provider, context: Context
):
    request = AsyncHTTPRequest(
        TestingRequestAdapter(
            method="GET",
            url="http://localhost:8000/test/callback",
            query_params={
                "code": "test_code",
                "state": "test_state",
            },
        )
    )

    response = await oauth_provider.callback(request, context)

    assert response.status_code == 400
    assert response.headers is not None
    assert response.headers["Content-Type"] == "application/json"
    assert response.json() == {
        "error": "server_error",
        "error_description": "Provider data not found",
    }


async def test_fails_if_there_was_no_code_in_request(
    oauth_provider: OAuth2Provider,
    context: Context,
    secondary_storage: SecondaryStorage,
):
    request = AsyncHTTPRequest(
        TestingRequestAdapter(
            method="GET",
            url="http://localhost:8000/test/callback",
            query_params={
                "state": "test_state",
            },
        )
    )

    secondary_storage.set(
        "oauth:authorization_request:test_state",
        json.dumps(
            {
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

    response = await oauth_provider.callback(request, context)

    assert response.status_code == 302
    assert response.headers is not None
    assert response.headers["Location"] == snapshot(
        "http://valid-frontend.com/callback?error=server_error&error_description=No+authorization+code+received+in+callback&state=test_client_state"
    )


async def test_fails_if_there_was_no_state_in_request(
    oauth_provider: OAuth2Provider,
    context: Context,
    secondary_storage: SecondaryStorage,
):
    request = AsyncHTTPRequest(
        TestingRequestAdapter(
            method="GET",
            url="http://localhost:8000/test/callback",
            query_params={
                "code": "test_code",
            },
        )
    )

    response = await oauth_provider.callback(request, context)

    assert response.status_code == 400
    assert response.json() == {
        "error": "server_error",
        "error_description": "No state found in request",
    }


async def test_fails_if_the_token_exchange_fails(
    oauth_provider: OAuth2Provider,
    context: Context,
    respx_mock: MockRouter,
    valid_callback_request: AsyncHTTPRequest,
):
    respx_mock.post(oauth_provider.token_endpoint).mock(
        return_value=httpx.Response(
            status_code=200,
            json={
                "error": "incorrect_client_credentials",
                "error_description": "The client_id and/or client_secret passed are incorrect.",
            },
        )
    )

    response = await oauth_provider.callback(valid_callback_request, context)

    assert response.status_code == 302
    assert response.headers is not None
    assert response.headers["Location"] == snapshot(
        "http://valid-frontend.com/callback?error=server_error&error_description=Token+exchange+failed%3A+incorrect_client_credentials&state=test_client_state"
    )


async def test_fails_if_the_token_exchange_returns_an_error_response(
    oauth_provider: OAuth2Provider,
    context: Context,
    respx_mock: MockRouter,
    valid_callback_request: AsyncHTTPRequest,
):
    respx_mock.post(oauth_provider.token_endpoint).mock(
        return_value=httpx.Response(status_code=500)
    )

    response = await oauth_provider.callback(valid_callback_request, context)

    assert response.status_code == 302
    assert response.headers is not None
    assert response.headers["Location"] == snapshot(
        "http://valid-frontend.com/callback?error=server_error&error_description=Token+exchange+failed&state=test_client_state"
    )


async def test_fails_if_there_is_no_email_in_the_user_info_response(
    oauth_provider: OAuth2Provider,
    context: Context,
    respx_mock: MockRouter,
    valid_callback_request: AsyncHTTPRequest,
):
    access_token = "test_access_token"

    data = {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "openid email profile",
    }

    respx_mock.post(oauth_provider.token_endpoint).mock(
        return_value=httpx.Response(
            status_code=200,
            json=data,
        )
    )
    respx_mock.get(oauth_provider.user_info_endpoint).mock(
        return_value=httpx.Response(status_code=200, json={"id": "test_id"})
    )

    response = await oauth_provider.callback(valid_callback_request, context)

    assert response.status_code == 302
    assert response.headers is not None
    assert response.headers["Location"] == snapshot(
        "http://valid-frontend.com/callback?error=server_error&error_description=No+email+found+in+user+info&state=test_client_state"
    )


async def test_fails_if_the_user_info_response_is_not_valid_json(
    oauth_provider: OAuth2Provider,
    context: Context,
    respx_mock: MockRouter,
    valid_callback_request: AsyncHTTPRequest,
):
    access_token = "test_access_token"

    data = {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "openid email profile",
    }

    respx_mock.post(oauth_provider.token_endpoint).mock(
        return_value=httpx.Response(
            status_code=200,
            json=data,
        )
    )

    respx_mock.get(oauth_provider.user_info_endpoint).mock(
        return_value=httpx.Response(status_code=200, content="not-valid-json")
    )

    response = await oauth_provider.callback(valid_callback_request, context)

    assert response.status_code == 302
    assert response.headers is not None
    assert response.headers["Location"] == snapshot(
        "http://valid-frontend.com/callback?error=server_error&error_description=Failed+to+fetch+user+info&state=test_client_state"
    )


async def test_fails_if_the_user_info_response_does_not_have_an_id(
    oauth_provider: OAuth2Provider,
    context: Context,
    respx_mock: MockRouter,
    valid_callback_request: AsyncHTTPRequest,
):
    access_token = "test_access_token"

    data = {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "openid email profile",
    }

    respx_mock.post(oauth_provider.token_endpoint).mock(
        return_value=httpx.Response(
            status_code=200,
            json=data,
        )
    )

    respx_mock.get(oauth_provider.user_info_endpoint).mock(
        return_value=httpx.Response(status_code=200, json={"email": "test@example.com"})
    )

    response = await oauth_provider.callback(valid_callback_request, context)

    assert response.status_code == 302
    assert response.headers is not None
    assert response.headers["Location"] == snapshot(
        "http://valid-frontend.com/callback?error=server_error&error_description=No+provider+user+ID+found+in+user+info&state=test_client_state"
    )


@time_machine.travel(
    datetime.datetime(2012, 10, 1, 1, 0, tzinfo=datetime.timezone.utc), tick=False
)
async def test_create_user_if_it_does_not_exist(
    oauth_provider: OAuth2Provider,
    context: Context,
    respx_mock: MockRouter,
    valid_callback_request: AsyncHTTPRequest,
    accounts_storage: MemoryAccountsStorage,
):
    access_token = "test_access_token"

    data = {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "openid email profile",
    }

    respx_mock.post(oauth_provider.token_endpoint).mock(
        return_value=httpx.Response(
            status_code=200,
            json=data,
        )
    )

    respx_mock.get(oauth_provider.user_info_endpoint).mock(
        return_value=httpx.Response(
            status_code=200,
            json={"email": "pollo@example.com", "id": "pollo", "social_accounts": []},
        )
    )

    response = await oauth_provider.callback(valid_callback_request, context)

    assert response.status_code == 302
    assert response.headers is not None
    assert response.headers["Location"] == snapshot(
        "http://valid-frontend.com/callback?code=a-totally-valid-code&state=test_client_state"
    )

    pollo = accounts_storage.data.get("pollo")

    assert pollo is not None
    assert pollo.social_accounts[0].provider == "test"
    assert pollo.social_accounts[0].provider_user_id == "pollo"
    assert pollo.social_accounts[0].access_token == access_token
    assert pollo.social_accounts[0].refresh_token is None
    assert pollo.social_accounts[0].access_token_expires_at == datetime.datetime(
        2012, 10, 1, 2, 0, tzinfo=datetime.timezone.utc
    )
    assert pollo.social_accounts[0].refresh_token_expires_at is None
    assert pollo.social_accounts[0].scope == "openid email profile"


@time_machine.travel(
    datetime.datetime(2012, 10, 1, 1, 0, tzinfo=datetime.timezone.utc), tick=False
)
async def test_stores_the_code_in_the_session(
    oauth_provider: OAuth2Provider,
    context: Context,
    respx_mock: MockRouter,
    valid_callback_request: AsyncHTTPRequest,
    secondary_storage: SecondaryStorage,
):
    access_token = "test_access_token"

    data = {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "openid email profile",
    }

    respx_mock.post(oauth_provider.token_endpoint).mock(
        return_value=httpx.Response(
            status_code=200,
            json=data,
        )
    )

    respx_mock.get(oauth_provider.user_info_endpoint).mock(
        return_value=httpx.Response(
            status_code=200,
            json={"email": "pollo@example.com", "id": "pollo", "social_accounts": []},
        )
    )

    response = await oauth_provider.callback(valid_callback_request, context)

    assert response.status_code == 302
    assert response.headers is not None
    assert response.headers["Location"] == snapshot(
        "http://valid-frontend.com/callback?code=a-totally-valid-code&state=test_client_state"
    )

    raw_auth_data = secondary_storage.get("oauth:code:a-totally-valid-code")

    assert raw_auth_data is not None

    auth_data = AuthorizationCodeGrantData.model_validate_json(raw_auth_data)

    assert auth_data.model_dump() == {
        "user_id": "pollo",
        "expires_at": datetime.datetime(
            2012, 10, 1, 1, 10, tzinfo=datetime.timezone.utc
        ),
        "client_id": "test_client_id",
        "redirect_uri": "http://valid-frontend.com/callback",
        "code_challenge": "test",
        "code_challenge_method": "S256",
    }


async def test_fails_if_there_is_user_with_the_same_email_but_different_provider(
    oauth_provider: OAuth2Provider,
    context: Context,
    respx_mock: MockRouter,
    valid_callback_request: AsyncHTTPRequest,
    accounts_storage: MemoryAccountsStorage,
):
    access_token = "test_access_token"

    accounts_storage.create_user(
        user_info={"email": "pollo@example.com", "id": "pollo"},
        email="pollo@example.com",
        email_verified=True,
    )

    accounts_storage.create_social_account(
        user_id="pollo",
        provider="other_provider",
        provider_user_id="other_provider_user_id",
        access_token=None,
        refresh_token=None,
        access_token_expires_at=None,
        refresh_token_expires_at=None,
        scope=None,
        user_info={"email": "pollo@example.com", "id": "pollo"},
        provider_email="pollo@example.com",
        provider_email_verified=True,
        is_login_method=True,
    )

    data = {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "openid email profile",
    }

    respx_mock.post(oauth_provider.token_endpoint).mock(
        return_value=httpx.Response(
            status_code=200,
            json=data,
        )
    )

    respx_mock.get(oauth_provider.user_info_endpoint).mock(
        return_value=httpx.Response(
            status_code=200,
            json={"email": "pollo@example.com", "id": "pollo", "social_accounts": []},
        )
    )

    response = await oauth_provider.callback(valid_callback_request, context)

    assert response.status_code == 302
    assert response.headers is not None
    assert response.headers["Location"] == snapshot(
        "http://valid-frontend.com/callback?error=account_not_linked&error_description=An+account+with+this+email+exists+but+could+not+be+linked+automatically.&state=test_client_state"
    )


async def test_works_when_there_is_user_with_the_same_email_and_provider(
    oauth_provider: OAuth2Provider,
    context: Context,
    respx_mock: MockRouter,
    valid_callback_request: AsyncHTTPRequest,
    accounts_storage: MemoryAccountsStorage,
):
    accounts_storage.create_user(
        user_info={"email": "pollo@example.com", "id": "pollo"},
        email="pollo@example.com",
        email_verified=True,
    )

    accounts_storage.create_social_account(
        user_id="pollo",
        provider="test",
        provider_user_id="pollo",
        access_token=None,
        refresh_token=None,
        access_token_expires_at=None,
        refresh_token_expires_at=None,
        scope=None,
        user_info={"email": "pollo@example.com", "id": "pollo"},
        provider_email="pollo@example.com",
        provider_email_verified=True,
        is_login_method=True,
    )

    data = {
        "access_token": "test_access_token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "openid email profile",
    }

    respx_mock.post(oauth_provider.token_endpoint).mock(
        return_value=httpx.Response(
            status_code=200,
            json=data,
        )
    )

    respx_mock.get(oauth_provider.user_info_endpoint).mock(
        return_value=httpx.Response(
            status_code=200,
            json={"email": "pollo@example.com", "id": "pollo"},
        )
    )

    response = await oauth_provider.callback(valid_callback_request, context)

    assert response.status_code == 302
    assert response.headers is not None
    assert response.headers["Location"] == snapshot(
        "http://valid-frontend.com/callback?code=a-totally-valid-code&state=test_client_state"
    )

    assert accounts_storage.data.get("pollo")


@time_machine.travel(
    datetime.datetime(2012, 10, 1, 1, 0, tzinfo=datetime.timezone.utc), tick=False
)
async def test_updates_the_social_account_if_it_already_exists(
    oauth_provider: OAuth2Provider,
    context: Context,
    respx_mock: MockRouter,
    valid_callback_request: AsyncHTTPRequest,
    accounts_storage: MemoryAccountsStorage,
):
    accounts_storage.create_user(
        user_info={"email": "pollo@example.com", "id": "pollo"},
        email="pollo@example.com",
        email_verified=True,
    )

    accounts_storage.create_social_account(
        user_id="pollo",
        provider="test",
        provider_user_id="pollo",
        access_token="old_access_token",
        refresh_token="old_refresh_token",
        access_token_expires_at=None,
        refresh_token_expires_at=None,
        scope="old_scope",
        user_info={"email": "pollo@example.com", "id": "pollo"},
        provider_email="pollo@example.com",
        provider_email_verified=True,
        is_login_method=True,
    )

    data = {
        "access_token": "test_access_token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "openid email profile",
    }

    respx_mock.post(oauth_provider.token_endpoint).mock(
        return_value=httpx.Response(
            status_code=200,
            json=data,
        )
    )

    respx_mock.get(oauth_provider.user_info_endpoint).mock(
        return_value=httpx.Response(
            status_code=200,
            json={"email": "pollo@example.com", "id": "pollo"},
        )
    )

    response = await oauth_provider.callback(valid_callback_request, context)

    assert response.status_code == 302
    assert response.headers is not None
    assert response.headers["Location"] == snapshot(
        "http://valid-frontend.com/callback?code=a-totally-valid-code&state=test_client_state"
    )

    account = accounts_storage.data.get("pollo")

    assert account is not None
    assert account.social_accounts[0].provider == "test"
    assert account.social_accounts[0].provider_user_id == "pollo"
    assert account.social_accounts[0].access_token == "test_access_token"
    assert account.social_accounts[0].refresh_token is None


async def test_fails_if_the_user_is_not_allowed_to_signup(
    oauth_provider: OAuth2Provider,
    context: Context,
    respx_mock: MockRouter,
    valid_callback_request: AsyncHTTPRequest,
    secondary_storage: SecondaryStorage,
):
    access_token = "test_access_token"

    data = {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "openid email profile",
    }

    respx_mock.post(oauth_provider.token_endpoint).mock(
        return_value=httpx.Response(
            status_code=200,
            json=data,
        )
    )

    respx_mock.get(oauth_provider.user_info_endpoint).mock(
        return_value=httpx.Response(
            status_code=200,
            json={"email": "not-allowed@example.com", "id": "not-allowed"},
        )
    )

    response = await oauth_provider.callback(valid_callback_request, context)

    assert response.status_code == 302
    assert response.headers is not None
    assert response.headers["Location"] == snapshot(
        "http://valid-frontend.com/callback?error=email_not_invited&error_description=This+email+has+not+yet+been+invited+to+join+FastAPI+Cloud&state=test_client_state"
    )


async def test_callback_returns_client_state_for_csrf_protection(
    oauth_provider: OAuth2Provider,
    context: Context,
    secondary_storage: SecondaryStorage,
    respx_mock: MockRouter,
):
    """
    Test that the OAuth callback returns the client_state parameter
    back to the client application. This enables CSRF protection by
    allowing the client to validate that the OAuth response corresponds
    to their own authorization request.
    """
    # Client's state parameter for CSRF protection
    client_state = "client_csrf_token_abc123"
    provider_state = "provider_state_xyz"

    # Setup: Store authorization request data
    secondary_storage.set(
        f"oauth:authorization_request:{provider_state}",
        json.dumps(
            {
                "redirect_uri": "https://valid-frontend.com/callback",
                "login_hint": None,
                "state": provider_state,
                "client_state": client_state,  # This should be returned!
                "code_challenge": "test_challenge",
                "code_challenge_method": "S256",
                "provider_code_verifier": "test_provider_verifier",
            }
        ),
    )

    # Mock the provider's token endpoint
    respx_mock.post(oauth_provider.token_endpoint).mock(
        return_value=httpx.Response(
            status_code=200,
            json={
                "access_token": "test_token",
                "token_type": "Bearer",
                "expires_in": 3600,
            },
        )
    )

    # Mock the user info endpoint
    respx_mock.get(oauth_provider.user_info_endpoint).mock(
        return_value=httpx.Response(
            status_code=200,
            json={"email": "user@example.com", "id": "user_id"},
        )
    )

    # OAuth provider redirects back with code
    callback_response = await oauth_provider.callback(
        AsyncHTTPRequest(
            TestingRequestAdapter(
                method="GET",
                url="http://localhost:8000/test/callback",
                query_params={
                    "code": "provider_code",
                    "state": provider_state,
                },
            )
        ),
        context,
    )

    # The callback should redirect with both code AND state
    assert callback_response.status_code == 302
    assert callback_response.headers is not None
    callback_redirect = callback_response.headers["Location"]

    # The redirect should include the authorization code
    assert "code=" in callback_redirect

    # The redirect should include the client_state for CSRF validation
    assert f"state={client_state}" in callback_redirect
    assert callback_redirect == snapshot(
        f"https://valid-frontend.com/callback?code=a-totally-valid-code&state={client_state}"
    )
