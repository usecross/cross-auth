from datetime import datetime, timedelta, timezone

import pytest
from cross_web import AsyncHTTPRequest
from inline_snapshot import snapshot

from cross_auth._context import Context
from cross_auth._issuer import AuthorizationCodeGrantData, Issuer
from cross_auth._storage import SecondaryStorage

pytestmark = pytest.mark.asyncio


async def test_issuer(issuer: Issuer):
    (token_route,) = issuer.routes

    assert token_route.path == "/token"
    assert token_route.methods == ["POST"]
    assert token_route.function == issuer.token


async def test_returns_error_response_if_client_id_is_missing(
    issuer: Issuer, context: Context
):
    response = await issuer.token(
        AsyncHTTPRequest.from_form_data(data={"grant_type": "authorization_code"}),
        context,
    )
    assert response.status_code == 400
    assert response.json() == snapshot(
        {"error": "invalid_request", "error_description": "client_id is required"}
    )


async def test_returns_error_response_if_grant_type_is_missing(
    issuer: Issuer, context: Context
):
    response = await issuer.token(
        AsyncHTTPRequest.from_form_data(data={"client_id": "test"}), context
    )
    assert response.status_code == 400
    assert response.json() == snapshot(
        {
            "error": "invalid_request",
            "error_description": "grant_type is required",
        }
    )


async def test_returns_error_for_unsupported_grant_type(
    issuer: Issuer, context: Context
):
    response = await issuer.token(
        AsyncHTTPRequest.from_form_data(
            data={"grant_type": "client_credentials", "client_id": "test"}
        ),
        context,
    )

    assert response.status_code == 400
    assert response.json() == snapshot(
        {
            "error": "unsupported_grant_type",
            "error_description": "Grant type 'client_credentials' is not supported",
        }
    )


async def test_returns_error_response_if_code_is_missing(
    issuer: Issuer, context: Context
):
    response = await issuer.token(
        AsyncHTTPRequest.from_form_data(
            data={"grant_type": "authorization_code", "client_id": "test"}
        ),
        context,
    )
    assert response.status_code == 400
    assert response.json() == snapshot(
        {"error": "invalid_request", "error_description": "code is required"}
    )


async def test_returns_error_response_if_redirect_uri_is_missing(
    issuer: Issuer, context: Context
):
    response = await issuer.token(
        AsyncHTTPRequest.from_form_data(
            data={
                "grant_type": "authorization_code",
                "client_id": "test",
                "code": "test",
            }
        ),
        context,
    )
    assert response.status_code == 400
    assert response.json() == snapshot(
        {"error": "invalid_request", "error_description": "redirect_uri is required"}
    )


async def test_returns_error_response_if_code_is_invalid(
    issuer: Issuer, context: Context
):
    response = await issuer.token(
        AsyncHTTPRequest.from_form_data(
            data={
                "grant_type": "authorization_code",
                "client_id": "test",
                "code": "test",
                "redirect_uri": "test",
                "code_verifier": "test",
            }
        ),
        context,
    )

    assert response.status_code == 400
    assert response.json() == snapshot(
        {"error": "invalid_grant", "error_description": "Authorization code not found"}
    )


async def test_returns_error_response_if_code_has_expired(
    issuer: Issuer, context: Context, expired_code: str
):
    response = await issuer.token(
        AsyncHTTPRequest.from_form_data(
            data={
                "grant_type": "authorization_code",
                "client_id": "test",
                "code": expired_code,
                "redirect_uri": "test",
                "code_verifier": "test",
            }
        ),
        context,
    )

    assert response.status_code == 400
    assert response.json() == snapshot(
        {
            "error": "invalid_grant",
            "error_description": "Authorization code has expired",
        }
    )


async def test_returns_error_response_if_redirect_uri_does_not_match(
    issuer: Issuer, context: Context, valid_code: str
):
    response = await issuer.token(
        AsyncHTTPRequest.from_form_data(
            data={
                "grant_type": "authorization_code",
                "client_id": "test",
                "code": valid_code,
                "redirect_uri": "test2",
                "code_verifier": "test",
            }
        ),
        context,
    )

    assert response.status_code == 400
    assert response.json() == snapshot(
        {"error": "invalid_grant", "error_description": "Redirect URI does not match"}
    )


async def test_returns_error_response_if_code_verifier_is_missing(
    issuer: Issuer, context: Context, valid_code: str
):
    response = await issuer.token(
        AsyncHTTPRequest.from_form_data(
            data={
                "grant_type": "authorization_code",
                "client_id": "test",
                "code": valid_code,
                "redirect_uri": "test",
            }
        ),
        context,
    )

    assert response.status_code == 400
    assert response.json() == snapshot(
        {"error": "invalid_request", "error_description": "code_verifier is required"}
    )


async def test_returns_error_response_if_client_id_does_not_match(
    issuer: Issuer, context: Context, secondary_storage: SecondaryStorage
):
    """
    Test that an authorization code issued to one client cannot be
    exchanged by a different client. This prevents authorization code
    theft attacks where an attacker intercepts a code and tries to
    exchange it using their own client_id.
    """
    code = "test_code_for_specific_client"
    secondary_storage.set(
        f"oauth:code:{code}",
        AuthorizationCodeGrantData(
            user_id="test",
            expires_at=datetime.now(tz=timezone.utc) + timedelta(seconds=10),
            client_id="legit-client",  # Code issued to "legit-client"
            redirect_uri="test",
            code_challenge="n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
            code_challenge_method="S256",
        ).model_dump_json(),
    )

    # Attempt to exchange with different client_id
    response = await issuer.token(
        AsyncHTTPRequest.from_form_data(
            data={
                "grant_type": "authorization_code",
                "client_id": "attacker-client",  # Different client!
                "code": code,
                "redirect_uri": "test",
                "code_verifier": "test",
            }
        ),
        context,
    )

    assert response.status_code == 400
    assert response.json() == snapshot(
        {"error": "invalid_grant", "error_description": "Client ID does not match"}
    )


async def test_returns_token_if_code_is_valid(
    issuer: Issuer, context: Context, valid_code: str
):
    response = await issuer.token(
        AsyncHTTPRequest.from_form_data(
            data={
                "grant_type": "authorization_code",
                "client_id": "test",
                "code": valid_code,
                "redirect_uri": "test",
                "code_verifier": "test",
            }
        ),
        context,
    )

    assert response.status_code == 200
    assert response.json() == snapshot(
        {
            "access_token": "token-test",
            "token_type": "Bearer",
            "expires_in": 0,
            "refresh_token": None,
            "refresh_token_expires_in": None,
            "scope": "",
            "id_token": None,
        }
    )


async def test_authorization_code_can_only_be_used_once(
    issuer: Issuer, context: Context, valid_code: str
):
    """
    Test that authorization codes can only be used once.
    This prevents race condition attacks where an attacker tries to
    reuse an intercepted authorization code.
    """
    # First exchange should succeed
    response1 = await issuer.token(
        AsyncHTTPRequest.from_form_data(
            data={
                "grant_type": "authorization_code",
                "client_id": "test",
                "code": valid_code,
                "redirect_uri": "test",
                "code_verifier": "test",
            }
        ),
        context,
    )

    assert response1.status_code == 200

    # Second attempt with same code should fail
    response2 = await issuer.token(
        AsyncHTTPRequest.from_form_data(
            data={
                "grant_type": "authorization_code",
                "client_id": "test",
                "code": valid_code,
                "redirect_uri": "test",
                "code_verifier": "test",
            }
        ),
        context,
    )

    assert response2.status_code == 400
    assert response2.json() == snapshot(
        {"error": "invalid_grant", "error_description": "Authorization code not found"}
    )


async def test_password_grant_missing_username(issuer: Issuer, context: Context):
    response = await issuer.token(
        AsyncHTTPRequest.from_form_data(
            data={
                "grant_type": "password",
                "client_id": "test",
                "password": "password123",
            }
        ),
        context,
    )
    assert response.status_code == 400
    assert response.json() == snapshot(
        {"error": "invalid_request", "error_description": "username is required"}
    )


async def test_password_grant_missing_password(issuer: Issuer, context: Context):
    response = await issuer.token(
        AsyncHTTPRequest.from_form_data(
            data={
                "grant_type": "password",
                "client_id": "test",
                "username": "test@example.com",
            }
        ),
        context,
    )
    assert response.status_code == 400
    assert response.json() == snapshot(
        {"error": "invalid_request", "error_description": "password is required"}
    )


async def test_password_grant_invalid_credentials(issuer: Issuer, context: Context):
    response = await issuer.token(
        AsyncHTTPRequest.from_form_data(
            data={
                "grant_type": "password",
                "client_id": "test",
                "username": "test@example.com",
                "password": "wrong_password",
            }
        ),
        context,
    )
    assert response.status_code == 400
    assert response.json() == snapshot(
        {"error": "invalid_grant", "error_description": "Invalid username or password"}
    )


async def test_password_grant_invalid_username(issuer: Issuer, context: Context):
    response = await issuer.token(
        AsyncHTTPRequest.from_form_data(
            data={
                "grant_type": "password",
                "client_id": "test",
                "username": "nonexistent@example.com",
                "password": "password123",
            }
        ),
        context,
    )
    assert response.status_code == 400
    assert response.json() == snapshot(
        {"error": "invalid_grant", "error_description": "Invalid username or password"}
    )


async def test_password_grant_success(issuer: Issuer, context: Context):
    response = await issuer.token(
        AsyncHTTPRequest.from_form_data(
            data={
                "grant_type": "password",
                "client_id": "test",
                "username": "test@example.com",
                "password": "password123",
            }
        ),
        context,
    )
    assert response.status_code == 200
    assert response.json() == snapshot(
        {
            "access_token": "token-test",
            "token_type": "Bearer",
            "expires_in": 0,
            "refresh_token": None,
            "refresh_token_expires_in": None,
            "scope": "",
            "id_token": None,
        }
    )


async def test_password_grant_with_scope(issuer: Issuer, context: Context):
    response = await issuer.token(
        AsyncHTTPRequest.from_form_data(
            data={
                "grant_type": "password",
                "client_id": "test",
                "username": "test@example.com",
                "password": "password123",
                "scope": "",
            }
        ),
        context,
    )
    assert response.status_code == 200
    assert response.json() == snapshot(
        {
            "access_token": "token-test",
            "token_type": "Bearer",
            "expires_in": 0,
            "refresh_token": None,
            "refresh_token_expires_in": None,
            "scope": "",
            "id_token": None,
        }
    )


async def test_password_grant_has_consistent_timing(issuer: Issuer, context: Context):
    """
    Test that password grant has consistent timing for existing and non-existing users.
    This prevents timing attacks that could be used to enumerate valid user accounts.

    Both scenarios should take roughly the same time because we always perform
    password verification, even for non-existent users (using a dummy hash).
    """
    import time

    # Measure timing for non-existent user (should run dummy hash verification)
    nonexistent_times = []
    for _ in range(3):
        start = time.perf_counter()
        await issuer.token(
            AsyncHTTPRequest.from_form_data(
                data={
                    "grant_type": "password",
                    "client_id": "test",
                    "username": "nonexistent@example.com",
                    "password": "wrong_password",
                }
            ),
            context,
        )
        end = time.perf_counter()
        nonexistent_times.append(end - start)

    # Measure timing for existing user with wrong password (should run real hash verification)
    existing_times = []
    for _ in range(3):
        start = time.perf_counter()
        await issuer.token(
            AsyncHTTPRequest.from_form_data(
                data={
                    "grant_type": "password",
                    "client_id": "test",
                    "username": "test@example.com",
                    "password": "wrong_password",
                }
            ),
            context,
        )
        end = time.perf_counter()
        existing_times.append(end - start)

    avg_nonexistent = sum(nonexistent_times) / len(nonexistent_times)
    avg_existing = sum(existing_times) / len(existing_times)
    difference = abs(avg_existing - avg_nonexistent)

    # The timing difference should be minimal (<50ms)
    # If it's larger, it indicates a timing attack vulnerability
    assert difference < 0.05, (
        f"Timing difference too large: {difference*1000:.2f}ms. "
        f"Non-existent: {avg_nonexistent*1000:.2f}ms, "
        f"Existing: {avg_existing*1000:.2f}ms"
    )
