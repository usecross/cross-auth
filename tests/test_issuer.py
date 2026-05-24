from datetime import datetime, timedelta, timezone
from unittest import mock

from cross_web import HTTPRequest
from inline_snapshot import snapshot

from cross_auth._context import Context
from cross_auth._issuer import AuthorizationCodeGrantData, Issuer
from cross_auth._password import DUMMY_PASSWORD_HASH
from cross_auth._storage import SecondaryStorage
from cross_auth.exceptions import CrossAuthException
from cross_auth.hooks import BeforeTokenPasswordEvent

from .conftest import MemorySessionStorage


def test_issuer(issuer: Issuer):
    (token_route,) = issuer.routes

    assert token_route.path == "/token"
    assert token_route.methods == ["POST"]
    assert token_route.function == issuer.token


def test_returns_error_response_if_client_id_is_missing(
    issuer: Issuer, context: Context
):
    response = issuer.token(
        HTTPRequest.from_form_data(data={"grant_type": "authorization_code"}),
        context,
    )
    assert response.status_code == 400
    assert response.json() == snapshot(
        {"error": "invalid_request", "error_description": "client_id is required"}
    )


def test_returns_error_response_if_grant_type_is_missing(
    issuer: Issuer, context: Context
):
    response = issuer.token(
        HTTPRequest.from_form_data(data={"client_id": "test"}), context
    )
    assert response.status_code == 400
    assert response.json() == snapshot(
        {
            "error": "invalid_request",
            "error_description": "grant_type is required",
        }
    )


def test_returns_error_for_unsupported_grant_type(issuer: Issuer, context: Context):
    response = issuer.token(
        HTTPRequest.from_form_data(
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


def test_returns_error_response_if_code_is_missing(issuer: Issuer, context: Context):
    response = issuer.token(
        HTTPRequest.from_form_data(
            data={"grant_type": "authorization_code", "client_id": "test"}
        ),
        context,
    )
    assert response.status_code == 400
    assert response.json() == snapshot(
        {"error": "invalid_request", "error_description": "code is required"}
    )


def test_returns_error_response_if_redirect_uri_is_missing(
    issuer: Issuer, context: Context
):
    response = issuer.token(
        HTTPRequest.from_form_data(
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


def test_returns_error_response_if_code_is_invalid(issuer: Issuer, context: Context):
    response = issuer.token(
        HTTPRequest.from_form_data(
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


def test_returns_error_response_if_code_has_expired(
    issuer: Issuer, context: Context, expired_code: str
):
    response = issuer.token(
        HTTPRequest.from_form_data(
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


def test_returns_error_response_if_redirect_uri_does_not_match(
    issuer: Issuer, context: Context, valid_code: str
):
    response = issuer.token(
        HTTPRequest.from_form_data(
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


def test_returns_error_response_if_code_verifier_is_missing(
    issuer: Issuer, context: Context, valid_code: str
):
    response = issuer.token(
        HTTPRequest.from_form_data(
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


def test_returns_error_response_if_client_id_does_not_match(
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
    response = issuer.token(
        HTTPRequest.from_form_data(
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


def test_returns_opaque_session_token_if_code_is_valid(
    issuer: Issuer,
    context: Context,
    valid_code: str,
    session_storage: MemorySessionStorage,
):
    response = issuer.token(
        HTTPRequest.from_form_data(
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
            "access_token": mock.ANY,
            "token_type": "Bearer",
            "expires_in": 86400,
            "refresh_token": None,
            "refresh_token_expires_in": None,
            "scope": "",
            "id_token": None,
        }
    )
    assert [
        {
            "token_hash": record.token_hash,
            "user_id": record.user_id,
            "client_id": record.client_id,
        }
        for record in session_storage.records.values()
    ] == snapshot(
        [
            {
                "token_hash": mock.ANY,
                "user_id": "test",
                "client_id": "test",
            }
        ]
    )


def test_authorization_code_grant_uses_token_issuer_without_session_storage(
    issuer: Issuer,
    secondary_storage: SecondaryStorage,
    accounts_storage,
    valid_code: str,
):
    issued_requests = []

    def issue_token(request):
        issued_requests.append(request)
        return "stateless-token", 3600

    context = Context(
        secondary_storage=secondary_storage,
        accounts_storage=accounts_storage,
        session_storage=None,
        token_issuer=issue_token,
        get_user_from_request=lambda _: None,
        trusted_origins=["valid-frontend.com"],
    )

    http_request = HTTPRequest.from_form_data(
        data={
            "grant_type": "authorization_code",
            "client_id": "test",
            "code": valid_code,
            "redirect_uri": "test",
            "code_verifier": "test",
        }
    )

    response = issuer.token(http_request, context)

    assert response.status_code == 200
    assert response.json() == snapshot(
        {
            "access_token": "stateless-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": None,
            "refresh_token_expires_in": None,
            "scope": "",
            "id_token": None,
        }
    )

    [token_request] = issued_requests
    assert token_request.user_id == "test"
    assert token_request.client_id == "test"
    assert token_request.grant_type == "authorization_code"
    assert token_request.scope is None
    assert token_request.username is None
    assert token_request.http_request is http_request


def test_password_grant_uses_token_issuer_without_session_storage(
    issuer: Issuer,
    secondary_storage: SecondaryStorage,
    accounts_storage,
):
    issued_requests = []

    def issue_token(request):
        issued_requests.append(request)
        return "password-token", 1800

    context = Context(
        secondary_storage=secondary_storage,
        accounts_storage=accounts_storage,
        session_storage=None,
        token_issuer=issue_token,
        get_user_from_request=lambda _: None,
        trusted_origins=["valid-frontend.com"],
    )

    http_request = HTTPRequest.from_form_data(
        data={
            "grant_type": "password",
            "client_id": "test",
            "username": "test@example.com",
            "password": "password123",
            "scope": "read write",
        }
    )

    response = issuer.token(http_request, context)

    assert response.status_code == 200
    assert response.json() == snapshot(
        {
            "access_token": "password-token",
            "token_type": "Bearer",
            "expires_in": 1800,
            "refresh_token": None,
            "refresh_token_expires_in": None,
            "scope": "",
            "id_token": None,
        }
    )

    [token_request] = issued_requests
    assert token_request.user_id == "test"
    assert token_request.client_id == "test"
    assert token_request.grant_type == "password"
    assert token_request.scope == "read write"
    assert token_request.username == "test@example.com"
    assert token_request.http_request is http_request


def test_token_endpoint_errors_without_token_issuer_or_session_storage(
    issuer: Issuer,
    secondary_storage: SecondaryStorage,
    accounts_storage,
    valid_code: str,
):
    context = Context(
        secondary_storage=secondary_storage,
        accounts_storage=accounts_storage,
        session_storage=None,
        get_user_from_request=lambda _: None,
        trusted_origins=["valid-frontend.com"],
    )

    response = issuer.token(
        HTTPRequest.from_form_data(
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

    assert response.status_code == 400
    assert response.json() == snapshot(
        {
            "error": "server_error",
            "error_description": (
                "The token endpoint requires token_issuer or session_storage"
            ),
        }
    )


def test_authorization_code_can_only_be_used_once(
    issuer: Issuer, context: Context, valid_code: str
):
    """
    Test that authorization codes can only be used once.
    This prevents race condition attacks where an attacker tries to
    reuse an intercepted authorization code.
    """
    # First exchange should succeed
    response1 = issuer.token(
        HTTPRequest.from_form_data(
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
    response2 = issuer.token(
        HTTPRequest.from_form_data(
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


def test_password_grant_missing_username(issuer: Issuer, context: Context):
    response = issuer.token(
        HTTPRequest.from_form_data(
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


def test_password_grant_missing_password(issuer: Issuer, context: Context):
    response = issuer.token(
        HTTPRequest.from_form_data(
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


def test_password_grant_invalid_credentials(issuer: Issuer, context: Context):
    response = issuer.token(
        HTTPRequest.from_form_data(
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


def test_password_grant_invalid_username(issuer: Issuer, context: Context):
    response = issuer.token(
        HTTPRequest.from_form_data(
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


def test_password_grant_preserves_unknown_hook_error_type(
    issuer: Issuer,
    context: Context,
):
    def reject_request(event: BeforeTokenPasswordEvent) -> None:
        raise CrossAuthException("forbidden", "Password grant is forbidden")

    context.hooks.register_before(
        "token.password",
        reject_request,
    )

    response = issuer.token(
        HTTPRequest.from_form_data(
            data={
                "grant_type": "password",
                "client_id": "test",
                "username": "test@example.com",
                "password": "password123",
            }
        ),
        context,
    )

    assert response.status_code == 400
    assert response.json() == snapshot(
        {
            "error": "forbidden",
            "error_description": "Password grant is forbidden",
        }
    )


def test_password_grant_success(
    issuer: Issuer,
    context: Context,
    session_storage: MemorySessionStorage,
):
    response = issuer.token(
        HTTPRequest.from_form_data(
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
            "access_token": mock.ANY,
            "token_type": "Bearer",
            "expires_in": 86400,
            "refresh_token": None,
            "refresh_token_expires_in": None,
            "scope": "",
            "id_token": None,
        }
    )
    assert [
        {
            "token_hash": record.token_hash,
            "user_id": record.user_id,
            "client_id": record.client_id,
        }
        for record in session_storage.records.values()
    ] == snapshot(
        [
            {
                "token_hash": mock.ANY,
                "user_id": "test",
                "client_id": "test",
            }
        ]
    )


def test_password_grant_with_scope(
    issuer: Issuer,
    context: Context,
    session_storage: MemorySessionStorage,
):
    response = issuer.token(
        HTTPRequest.from_form_data(
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
            "access_token": mock.ANY,
            "token_type": "Bearer",
            "expires_in": 86400,
            "refresh_token": None,
            "refresh_token_expires_in": None,
            "scope": "",
            "id_token": None,
        }
    )
    assert [
        {
            "token_hash": record.token_hash,
            "user_id": record.user_id,
            "client_id": record.client_id,
        }
        for record in session_storage.records.values()
    ] == snapshot(
        [
            {
                "token_hash": mock.ANY,
                "user_id": "test",
                "client_id": "test",
            }
        ]
    )


def test_password_grant_verifies_password_hash_for_unknown_users(
    issuer: Issuer,
    context: Context,
):
    existing_user = context.accounts_storage.find_user_by_email("test@example.com")
    assert existing_user is not None
    assert existing_user.hashed_password is not None

    verification_calls: list[tuple[str, str]] = []

    def record_password_verification(password: str, password_hash: str) -> bool:
        verification_calls.append((password, password_hash))
        return False

    def request_password_token(username: str):
        return issuer.token(
            HTTPRequest.from_form_data(
                data={
                    "grant_type": "password",
                    "client_id": "test",
                    "username": username,
                    "password": "wrong_password",
                }
            ),
            context,
        )

    with mock.patch(
        "cross_auth._password.pwd_context.verify",
        side_effect=record_password_verification,
    ):
        existing_response = request_password_token("test@example.com")
        unknown_response = request_password_token("nonexistent@example.com")

    assert existing_response.status_code == 400
    assert unknown_response.status_code == 400
    assert verification_calls == [
        ("wrong_password", existing_user.hashed_password),
        ("wrong_password", DUMMY_PASSWORD_HASH),
    ]
