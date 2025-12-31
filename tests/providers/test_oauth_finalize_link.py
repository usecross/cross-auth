import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest
import time_machine
from inline_snapshot import snapshot
from lia import AsyncHTTPRequest
from lia.request import TestingRequestAdapter
from respx import MockRouter

from cross_auth._context import Context, SecondaryStorage
from cross_auth._storage import AccountsStorage, User
from cross_auth.social_providers.oauth import OAuth2LinkCodeData, OAuth2Provider

pytestmark = pytest.mark.asyncio


@pytest.fixture
def context(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    logged_in_user: User,
) -> Context:
    """Override context with account linking enabled for finalize_link tests."""

    def _get_user_from_request(request: AsyncHTTPRequest) -> User | None:
        if request.headers.get("Authorization") == "Bearer test":
            return logged_in_user
        return None

    return Context(
        secondary_storage=secondary_storage,
        accounts_storage=accounts_storage,
        create_token=lambda id: (f"token-{id}", 0),
        get_user_from_request=_get_user_from_request,
        trusted_origins=["valid-frontend.com"],
        config={"account_linking": {"enabled": True}},
    )


async def test_fails_if_not_logged_in(
    oauth_provider: OAuth2Provider,
    context: Context,
) -> None:
    response = await oauth_provider.finalize_link(
        AsyncHTTPRequest(
            TestingRequestAdapter(
                method="POST",
                url="http://localhost:8000/test/finalize-link",
            )
        ),
        context,
    )

    assert response.status_code == 401
    assert response.json() == snapshot(
        {"error": "unauthorized", "error_description": "Not logged in"}
    )


async def test_fails_if_no_link_code_is_provided(
    oauth_provider: OAuth2Provider,
    context: Context,
) -> None:
    response = await oauth_provider.finalize_link(
        AsyncHTTPRequest(
            TestingRequestAdapter(
                method="POST",
                url="http://localhost:8000/test/finalize-link",
                headers={"Authorization": "Bearer test"},
                json={},
            )
        ),
        context,
    )

    assert response.status_code == 400
    assert response.json() == snapshot(
        {"error": "server_error", "error_description": "No link code found in request"}
    )


async def test_fails_if_data_is_missing(
    oauth_provider: OAuth2Provider,
    context: Context,
) -> None:
    response = await oauth_provider.finalize_link(
        AsyncHTTPRequest(
            TestingRequestAdapter(
                method="POST",
                url="http://localhost:8000/test/finalize-link",
                json={"link_code": "non-existent-code"},
                headers={"Authorization": "Bearer test"},
            )
        ),
        context,
    )

    assert response.status_code == 400
    assert response.json() == snapshot(
        {
            "error": "server_error",
            "error_description": "No link data found in secondary storage",
        }
    )


async def test_fails_if_data_is_invalid(
    oauth_provider: OAuth2Provider,
    context: Context,
    secondary_storage: SecondaryStorage,
) -> None:
    secondary_storage.set(
        "oauth:link_request:test_code",
        json.dumps({"invalid": "data"}),
    )

    response = await oauth_provider.finalize_link(
        AsyncHTTPRequest(
            TestingRequestAdapter(
                method="POST",
                url="http://localhost:8000/test/finalize-link",
                json={"link_code": "test_code"},
                headers={"Authorization": "Bearer test"},
            )
        ),
        context,
    )

    assert response.status_code == 400
    assert response.json() == snapshot(
        {
            "error": "server_error",
            "error_description": "Invalid link data",
        }
    )


@time_machine.travel(datetime(2012, 10, 1, 1, 0, tzinfo=timezone.utc), tick=False)
async def test_fails_if_code_has_expired(
    oauth_provider: OAuth2Provider,
    context: Context,
    secondary_storage: SecondaryStorage,
) -> None:
    secondary_storage.set(
        "oauth:link_request:test_code",
        json.dumps(
            {
                "expires_at": "2012-10-01T00:00:00Z",
                "client_id": "test_client_id",
                "redirect_uri": "http://localhost:8000/test/redirect",
                "code_challenge": "test_code_challenge",
                "code_challenge_method": "S256",
                "user_id": "test",
                "provider_code": "1234567890",
            }
        ),
    )

    response = await oauth_provider.finalize_link(
        AsyncHTTPRequest(
            TestingRequestAdapter(
                method="POST",
                url="http://localhost:8000/test/finalize-link",
                json={"link_code": "test_code"},
                headers={"Authorization": "Bearer test"},
            )
        ),
        context,
    )

    assert response.status_code == 400
    assert response.json() == snapshot(
        {
            "error": "server_error",
            "error_description": "Link code has expired",
        }
    )


@time_machine.travel(datetime(2012, 10, 1, 1, 0, tzinfo=timezone.utc), tick=False)
async def test_fails_if_code_challenge_is_missing(
    oauth_provider: OAuth2Provider,
    context: Context,
    secondary_storage: SecondaryStorage,
) -> None:
    secondary_storage.set(
        "oauth:link_request:test_code",
        json.dumps(
            {
                "expires_at": "2012-10-02T00:00:00Z",
                "client_id": "test_client_id",
                "redirect_uri": "http://localhost:8000/test/redirect",
                "code_challenge": "test_code_challenge",
                "code_challenge_method": "S256",
                "user_id": "test",
                "provider_code": "1234567890",
            }
        ),
    )

    response = await oauth_provider.finalize_link(
        AsyncHTTPRequest(
            TestingRequestAdapter(
                method="POST",
                url="http://localhost:8000/test/finalize-link",
                json={"link_code": "test_code"},
                headers={"Authorization": "Bearer test"},
            )
        ),
        context,
    )

    assert response.status_code == 400
    assert response.json() == snapshot(
        {
            "error": "server_error",
            "error_description": "No code_verifier provided",
        }
    )


@time_machine.travel(datetime(2012, 10, 1, 1, 0, tzinfo=timezone.utc), tick=False)
async def test_fails_if_code_challenge_is_invalid(
    oauth_provider: OAuth2Provider,
    context: Context,
    secondary_storage: SecondaryStorage,
) -> None:
    secondary_storage.set(
        "oauth:link_request:test_code",
        json.dumps(
            {
                "expires_at": "2012-10-02T00:00:00Z",
                "client_id": "test_client_id",
                "redirect_uri": "http://localhost:8000/test/redirect",
                "code_challenge": "test_code_challenge",
                "code_challenge_method": "S256",
                "user_id": "test",
                "provider_code": "1234567890",
            }
        ),
    )

    response = await oauth_provider.finalize_link(
        AsyncHTTPRequest(
            TestingRequestAdapter(
                method="POST",
                url="http://localhost:8000/test/finalize-link",
                json={
                    "link_code": "test_code",
                    "code_verifier": "test_code_verifier",
                },
                headers={"Authorization": "Bearer test"},
            )
        ),
        context,
    )

    assert response.status_code == 400
    assert response.json() == snapshot(
        {
            "error": "server_error",
            "error_description": "Invalid code challenge",
        }
    )


@time_machine.travel(datetime(2012, 10, 1, 1, 0, tzinfo=timezone.utc), tick=False)
async def test_fails_if_link_code_belongs_to_different_user(
    oauth_provider: OAuth2Provider,
    context: Context,
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
) -> None:
    """
    Test that link codes can only be used by the user who initiated the link flow.
    This prevents account takeover attacks where an attacker tricks a victim
    into using the attacker's link code.
    """
    # Create a different user (not the logged-in "test" user)
    _other_user = accounts_storage.create_user(
        user_info={"email": "other@example.com", "id": "other"},
        email="other@example.com",
        email_verified=True,
    )

    # Create a link code that belongs to the other user
    other_user_link_code = "other_user_link_code"

    secondary_storage.set(
        f"oauth:link_request:{other_user_link_code}",
        json.dumps(
            {
                "expires_at": "2012-10-02T00:00:00Z",
                "client_id": "test_client_id",
                "redirect_uri": "http://localhost:8000/test/redirect",
                "code_challenge": "n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
                "code_challenge_method": "S256",
                "user_id": "other",  # Belongs to "other" user!
                "provider_code": "1234567890",
            }
        ),
    )

    # The logged-in user is "test", but they try to use "other"'s link code
    response = await oauth_provider.finalize_link(
        AsyncHTTPRequest(
            TestingRequestAdapter(
                method="POST",
                url="http://localhost:8000/test/finalize-link",
                json={
                    "link_code": other_user_link_code,
                    "code_verifier": "test",
                },
                headers={"Authorization": "Bearer test"},  # Logged in as "test"
            )
        ),
        context,
    )

    # Should fail with 403 Forbidden
    assert response.status_code == 403
    assert response.json() == snapshot(
        {
            "error": "unauthorized",
            "error_description": "Link code does not belong to current user",
        }
    )


@time_machine.travel(datetime(2012, 10, 1, 1, 0, tzinfo=timezone.utc), tick=False)
async def test_fails_if_account_already_exists_on_another_user(
    oauth_provider: OAuth2Provider,
    context: Context,
    accounts_storage: AccountsStorage,
    valid_link_code: str,
    respx_mock: MockRouter,
) -> None:
    # Create another user who already has the social account linked
    accounts_storage.create_user(
        user_info={"email": "other@example.com", "id": "other"},
        email="other@example.com",
        email_verified=True,
    )

    accounts_storage.create_social_account(
        user_id="other",
        provider="test",
        provider_user_id="existing_provider_id",
        access_token=None,
        access_token_expires_at=None,
        refresh_token=None,
        refresh_token_expires_at=None,
        scope=None,
        user_info={"email": "other@example.com", "id": "existing_provider_id"},
        provider_email="other@example.com",
        provider_email_verified=True,
        is_login_method=True,
    )

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

    # Provider returns same provider_user_id that's already linked to "other" user,
    # but with logged-in user's email so we pass the email match check
    respx_mock.get(oauth_provider.user_info_endpoint).mock(
        return_value=httpx.Response(
            status_code=200,
            json={"email": "test@example.com", "id": "existing_provider_id"},
        )
    )

    response = await oauth_provider.finalize_link(
        AsyncHTTPRequest(
            TestingRequestAdapter(
                method="POST",
                url="http://localhost:8000/test/finalize-link",
                # TODO: these should be in the body...
                json={
                    "link_code": valid_link_code,
                    "code_verifier": "test",
                },
                headers={"Authorization": "Bearer test"},
            )
        ),
        context,
    )

    assert response.status_code == 400
    assert response.json() == snapshot(
        {
            "error": "server_error",
            "error_description": "Social account already exists",
        }
    )


@time_machine.travel(datetime(2012, 10, 1, 1, 0, tzinfo=timezone.utc), tick=False)
async def test_fails_if_account_linking_disabled(
    oauth_provider: OAuth2Provider,
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    logged_in_user: User,
    valid_link_code: str,
    respx_mock: MockRouter,
) -> None:
    """Account linking must be enabled to finalize a link."""

    def _get_user_from_request(request: AsyncHTTPRequest) -> User | None:
        if request.headers.get("Authorization") == "Bearer test":
            return logged_in_user
        return None

    # Context with account linking disabled (default)
    context_disabled = Context(
        secondary_storage=secondary_storage,
        accounts_storage=accounts_storage,
        create_token=lambda id: (f"token-{id}", 0),
        get_user_from_request=_get_user_from_request,
        trusted_origins=["valid-frontend.com"],
        # No config = account linking disabled
    )

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

    respx_mock.get(oauth_provider.user_info_endpoint).mock(
        return_value=httpx.Response(
            status_code=200,
            json={"email": "test@example.com", "id": "provider_123"},
        )
    )

    response = await oauth_provider.finalize_link(
        AsyncHTTPRequest(
            TestingRequestAdapter(
                method="POST",
                url="http://localhost:8000/test/finalize-link",
                json={
                    "link_code": valid_link_code,
                    "code_verifier": "test",
                },
                headers={"Authorization": "Bearer test"},
            )
        ),
        context_disabled,
    )

    assert response.status_code == 400
    assert response.json() == snapshot(
        {
            "error": "linking_disabled",
            "error_description": "Account linking is not enabled.",
        }
    )


@time_machine.travel(datetime(2012, 10, 1, 1, 0, tzinfo=timezone.utc), tick=False)
async def test_links_to_correct_user(
    oauth_provider: OAuth2Provider,
    context: Context,
    accounts_storage: AccountsStorage,
    valid_link_code: str,
    logged_in_user: User,
    respx_mock: MockRouter,
) -> None:
    assert len(list(logged_in_user.social_accounts)) == 0

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
            # Use same email as logged-in user (test@example.com)
            json={"email": "test@example.com", "id": "provider_user_123"},
        )
    )

    response = await oauth_provider.finalize_link(
        AsyncHTTPRequest(
            TestingRequestAdapter(
                method="POST",
                url="http://localhost:8000/test/finalize-link",
                json={
                    "link_code": valid_link_code,
                    "code_verifier": "test",
                },
                headers={"Authorization": "Bearer test"},
            )
        ),
        context,
    )

    assert response.status_code == 200
    assert response.json() == snapshot({"message": "Link finalized"})

    user = accounts_storage.find_user_by_id(logged_in_user.id)

    assert user is not None

    social_accounts = list(user.social_accounts)

    assert len(social_accounts) == 1
    assert social_accounts[0].provider == "test"
    assert social_accounts[0].provider_user_id == "provider_user_123"


@time_machine.travel(datetime(2012, 10, 1, 1, 0, tzinfo=timezone.utc), tick=False)
async def test_link_with_pkce_sends_provider_code_and_verifier(
    oauth_provider: OAuth2Provider,
    context: Context,
    accounts_storage: AccountsStorage,
    logged_in_user: User,
    respx_mock: MockRouter,
    secondary_storage: SecondaryStorage,
) -> None:
    link_code = "test_link_code"
    provider_code = "github_auth_code_12345"
    provider_code_verifier = "test_provider_verifier"

    secondary_storage.set(
        f"oauth:link_request:{link_code}",
        OAuth2LinkCodeData(
            expires_at=datetime.now(tz=timezone.utc) + timedelta(seconds=10),
            client_id="test_client_id",
            redirect_uri="/frontend/redirect",
            code_challenge="n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
            code_challenge_method="S256",
            user_id="test",
            provider_code=provider_code,
            provider_code_verifier=provider_code_verifier,
        ).model_dump_json(),
    )

    respx_mock.post(
        oauth_provider.token_endpoint,
        data={
            "grant_type": "authorization_code",
            "code": provider_code,
            "redirect_uri": "http://localhost:8000/test/callback",
            "client_id": "test_client_id",
            "client_secret": "test_client_secret",
            "code_verifier": provider_code_verifier,
        },
        headers={
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    ).mock(
        return_value=httpx.Response(
            status_code=200,
            json={
                "access_token": "some-cool-token",
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": "openid email profile",
            },
        )
    )

    respx_mock.get(oauth_provider.user_info_endpoint).mock(
        return_value=httpx.Response(
            status_code=200,
            json={"email": "test@example.com", "id": "test_id"},
        )
    )

    response = await oauth_provider.finalize_link(
        AsyncHTTPRequest(
            TestingRequestAdapter(
                method="POST",
                url="http://localhost:8000/test/finalize-link",
                json={
                    "link_code": link_code,
                    "code_verifier": "test",
                },
                headers={"Authorization": "Bearer test"},
            )
        ),
        context,
    )

    assert response.status_code == 200
