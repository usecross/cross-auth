from fastapi.testclient import TestClient
from inline_snapshot import snapshot


def test_returns_error_response_if_grant_type_is_missing(
    client: TestClient,
) -> None:
    response = client.post("/token", data={"client_id": "test"})
    assert response.status_code == 400
    assert response.json() == snapshot(
        {
            "error": "invalid_request",
            "error_description": "grant_type is required",
        }
    )


def test_returns_error_response_if_code_is_missing(client: TestClient) -> None:
    response = client.post(
        "/token", data={"grant_type": "authorization_code", "client_id": "test"}
    )
    assert response.status_code == 400
    assert response.json() == snapshot(
        {"error": "invalid_request", "error_description": "code is required"}
    )


def test_returns_error_response_if_redirect_uri_is_missing(
    client: TestClient,
) -> None:
    response = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "client_id": "test",
            "code": "test",
        },
    )
    assert response.status_code == 400
    assert response.json() == snapshot(
        {"error": "invalid_request", "error_description": "redirect_uri is required"}
    )


def test_returns_error_response_if_code_verifier_is_missing(
    client: TestClient, valid_code: str
) -> None:
    response = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "client_id": "test",
            "code": valid_code,
            "redirect_uri": "test",
        },
    )
    assert response.status_code == 400
    assert response.json() == snapshot(
        {"error": "invalid_request", "error_description": "code_verifier is required"}
    )


def test_password_grant_missing_username(client: TestClient) -> None:
    response = client.post(
        "/token",
        data={
            "grant_type": "password",
            "client_id": "test",
            "password": "password123",
        },
    )
    assert response.status_code == 400
    assert response.json() == snapshot(
        {"error": "invalid_request", "error_description": "username is required"}
    )


def test_password_grant_missing_password(client: TestClient) -> None:
    response = client.post(
        "/token",
        data={
            "grant_type": "password",
            "client_id": "test",
            "username": "test@example.com",
        },
    )
    assert response.status_code == 400
    assert response.json() == snapshot(
        {"error": "invalid_request", "error_description": "password is required"}
    )


def test_issuer_route_validates_password_grant_missing_client_id(
    client: TestClient,
) -> None:
    response = client.post("/token", data={"grant_type": "password"})
    assert response.status_code == 400

    assert response.json() == snapshot(
        {"error": "invalid_request", "error_description": "client_id is required"}
    )


def test_issuer_route_validates_auth_code_missing_client_id(client: TestClient) -> None:
    response = client.post("/token", data={"grant_type": "authorization_code"})
    assert response.status_code == 400

    assert response.json() == snapshot(
        {"error": "invalid_request", "error_description": "client_id is required"}
    )


def test_returns_error_for_unsupported_grant_type(client: TestClient) -> None:
    response = client.post(
        "/token",
        data={"grant_type": "client_credentials", "client_id": "test"},
    )

    assert response.status_code == 400
    assert response.json() == snapshot(
        {
            "error": "unsupported_grant_type",
            "error_description": "Grant type 'client_credentials' is not supported",
        }
    )


def test_returns_error_response_if_code_is_invalid(client: TestClient) -> None:
    response = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "client_id": "test",
            "code": "test",
            "redirect_uri": "test",
            "code_verifier": "test",
        },
    )

    assert response.status_code == 400
    assert response.json() == snapshot(
        {"error": "invalid_grant", "error_description": "Authorization code not found"}
    )


def test_returns_error_response_if_code_has_expired(
    client: TestClient, expired_code: str
) -> None:
    response = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "client_id": "test",
            "code": expired_code,
            "redirect_uri": "test",
            "code_verifier": "test",
        },
    )

    assert response.status_code == 400
    assert response.json() == snapshot(
        {
            "error": "invalid_grant",
            "error_description": "Authorization code has expired",
        }
    )


def test_returns_error_response_if_redirect_uri_does_not_match(
    client: TestClient, valid_code: str
) -> None:
    response = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "client_id": "test",
            "code": valid_code,
            "redirect_uri": "test2",
            "code_verifier": "test",
        },
    )

    assert response.status_code == 400
    assert response.json() == snapshot(
        {"error": "invalid_grant", "error_description": "Redirect URI does not match"}
    )


def test_returns_token_if_code_is_valid(client: TestClient, valid_code: str) -> None:
    response = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "client_id": "test",
            "code": valid_code,
            "redirect_uri": "test",
            "code_verifier": "test",
        },
    )

    assert response.status_code == 200
    assert response.json() == snapshot(
        {
            "access_token": "",
            "token_type": "Bearer",
            "expires_in": 0,
            "refresh_token": None,
            "refresh_token_expires_in": None,
            "scope": "",
        }
    )


def test_password_grant_invalid_credentials(client: TestClient) -> None:
    response = client.post(
        "/token",
        data={
            "grant_type": "password",
            "client_id": "test",
            "username": "test@example.com",
            "password": "wrong_password",
        },
    )
    assert response.status_code == 400
    assert response.json() == snapshot(
        {"error": "invalid_grant", "error_description": "Invalid username or password"}
    )


def test_password_grant_invalid_username(client: TestClient) -> None:
    response = client.post(
        "/token",
        data={
            "grant_type": "password",
            "client_id": "test",
            "username": "nonexistent@example.com",
            "password": "password123",
        },
    )
    assert response.status_code == 400
    assert response.json() == snapshot(
        {"error": "invalid_grant", "error_description": "Invalid username or password"}
    )


def test_password_grant_success(client: TestClient) -> None:
    response = client.post(
        "/token",
        data={
            "grant_type": "password",
            "client_id": "test",
            "username": "test@example.com",
            "password": "password123",
        },
    )
    assert response.status_code == 200
    assert response.json() == snapshot(
        {
            "access_token": "",
            "token_type": "Bearer",
            "expires_in": 0,
            "refresh_token": None,
            "refresh_token_expires_in": None,
            "scope": "",
        }
    )


def test_password_grant_with_scope(client: TestClient) -> None:
    response = client.post(
        "/token",
        data={
            "grant_type": "password",
            "client_id": "test",
            "username": "test@example.com",
            "password": "password123",
            "scope": "",
        },
    )
    assert response.status_code == 200
    assert response.json() == snapshot(
        {
            "access_token": "",
            "token_type": "Bearer",
            "expires_in": 0,
            "refresh_token": None,
            "refresh_token_expires_in": None,
            "scope": "",
        }
    )
