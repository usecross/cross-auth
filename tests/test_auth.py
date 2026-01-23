"""Tests for email/password authentication endpoints."""

import json
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock

import pytest
from cross_web import AsyncHTTPRequest, Response

from cross_auth._auth import AuthManager
from cross_auth._context import Context

pytestmark = pytest.mark.asyncio


def parse_json_body(response: Response) -> dict[str, Any]:
    """Parse JSON response body, asserting it's not None."""
    assert response.body is not None, "Response body should not be None"
    return json.loads(response.body)


def assert_has_cookie(response: Response, name: str) -> None:
    """Assert that response has a cookie with the given name."""
    assert response.cookies is not None, "Response should have cookies"
    cookie_names = [c.name for c in response.cookies]
    assert name in cookie_names, f"Expected cookie '{name}' not found in {cookie_names}"


def get_cookie(response: Response, name: str):
    """Get a cookie from the response by name."""
    assert response.cookies is not None, "Response should have cookies"
    for cookie in response.cookies:
        if cookie.name == name:
            return cookie
    raise AssertionError(f"Cookie '{name}' not found")


def make_request(
    path: str = "/login",
    method: str = "POST",
    body: bytes | None = None,
    cookies: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    query_params: dict[str, str] | None = None,
) -> AsyncHTTPRequest:
    """Create a mock AsyncHTTPRequest for testing."""
    request = MagicMock(spec=AsyncHTTPRequest)
    # request.url should be a string (as per cross_web spec)
    request.url = f"http://localhost{path}"
    request.method = method
    request.cookies = cookies or {}
    request.headers = headers or {}
    request.query_params = query_params or {}

    async def get_body():
        return body or b""

    request.get_body = get_body
    return request


class TestSignup:
    async def test_signup_disabled(self, context_with_sessions: Context) -> None:
        """Should return 403 when signup is disabled."""
        manager = AuthManager(enable_signup=False)
        request = make_request(
            body=b'{"email": "new@example.com", "password": "password123"}'
        )

        response = await manager.signup(request, context_with_sessions)

        assert response.status_code == 403
        data = parse_json_body(response)
        assert data["error"] == "signup_disabled"

    async def test_signup_invalid_request(self, context_with_sessions: Context) -> None:
        """Should return 400 for invalid request body."""
        manager = AuthManager()
        request = make_request(body=b'{"email": "invalid-email"}')

        response = await manager.signup(request, context_with_sessions)

        assert response.status_code == 400
        data = parse_json_body(response)
        assert data["error"] == "invalid_request"

    async def test_signup_user_exists(
        self, context_with_sessions: Context, logged_in_user
    ) -> None:
        """Should return 409 when user already exists."""
        manager = AuthManager()
        request = make_request(
            body=f'{{"email": "{logged_in_user.email}", "password": "password123"}}'.encode()
        )

        response = await manager.signup(request, context_with_sessions)

        assert response.status_code == 409
        data = parse_json_body(response)
        assert data["error"] == "user_exists"

    async def test_signup_success_with_session(
        self, context_with_sessions: Context
    ) -> None:
        """Should create user and return session cookie."""
        manager = AuthManager()
        request = make_request(
            body=b'{"email": "new@example.com", "password": "password123"}'
        )

        response = await manager.signup(request, context_with_sessions)

        assert response.status_code == 200
        data = parse_json_body(response)
        assert "user" in data
        assert data["user"]["email"] == "new@example.com"
        assert data["user"]["email_verified"] is False

        # Should have session cookie
        assert response.cookies is not None
        assert len(response.cookies) == 1
        cookie = get_cookie(response, "session_id")
        assert cookie.value  # Should have a value

    async def test_signup_success_with_token(
        self, context_with_sessions: Context
    ) -> None:
        """Should create user and return token when response_type=token."""
        manager = AuthManager()
        request = make_request(
            body=b'{"email": "new2@example.com", "password": "password123"}',
            query_params={"response_type": "token"},
        )

        response = await manager.signup(request, context_with_sessions)

        assert response.status_code == 200
        data = parse_json_body(response)
        assert "access_token" in data
        assert data["token_type"] == "Bearer"
        assert "user" in data
        assert data["user"]["email"] == "new2@example.com"

        # Should NOT have session cookie
        assert not response.cookies

    async def test_signup_fallback_to_token_without_sessions(
        self, context: Context
    ) -> None:
        """Should return token when sessions not enabled."""
        manager = AuthManager()
        request = make_request(
            body=b'{"email": "new3@example.com", "password": "password123"}'
        )

        response = await manager.signup(request, context)

        assert response.status_code == 200
        data = parse_json_body(response)
        assert "access_token" in data


class TestLogin:
    async def test_login_invalid_request(self, context_with_sessions: Context) -> None:
        """Should return 400 for invalid request body."""
        manager = AuthManager()
        request = make_request(body=b"invalid json")

        response = await manager.login(request, context_with_sessions)

        assert response.status_code == 400
        data = parse_json_body(response)
        assert data["error"] == "invalid_request"

    async def test_login_invalid_credentials_nonexistent_user(
        self, context_with_sessions: Context
    ) -> None:
        """Should return 401 for nonexistent user."""
        manager = AuthManager()
        request = make_request(
            body=b'{"email": "nonexistent@example.com", "password": "password123"}'
        )

        response = await manager.login(request, context_with_sessions)

        assert response.status_code == 401
        data = parse_json_body(response)
        assert data["error"] == "invalid_credentials"

    async def test_login_invalid_credentials_wrong_password(
        self, context_with_sessions: Context, logged_in_user
    ) -> None:
        """Should return 401 for wrong password."""
        manager = AuthManager()
        request = make_request(
            body=f'{{"email": "{logged_in_user.email}", "password": "wrongpassword"}}'.encode()
        )

        response = await manager.login(request, context_with_sessions)

        assert response.status_code == 401
        data = parse_json_body(response)
        assert data["error"] == "invalid_credentials"

    async def test_login_success_with_session(
        self, context_with_sessions: Context, logged_in_user
    ) -> None:
        """Should authenticate and return session cookie."""
        manager = AuthManager()
        # Use TEST_PASSWORD which is hashed in the fixture
        request = make_request(
            body=f'{{"email": "{logged_in_user.email}", "password": "password123"}}'.encode()
        )

        response = await manager.login(request, context_with_sessions)

        assert response.status_code == 200
        data = parse_json_body(response)
        assert "user" in data
        assert data["user"]["email"] == logged_in_user.email

        # Should have session cookie
        assert response.cookies is not None
        assert len(response.cookies) == 1
        cookie = get_cookie(response, "session_id")
        assert cookie.value  # Should have a value

    async def test_login_success_with_token(
        self, context_with_sessions: Context, logged_in_user
    ) -> None:
        """Should authenticate and return token when response_type=token."""
        manager = AuthManager()
        request = make_request(
            body=f'{{"email": "{logged_in_user.email}", "password": "password123"}}'.encode(),
            query_params={"response_type": "token"},
        )

        response = await manager.login(request, context_with_sessions)

        assert response.status_code == 200
        data = parse_json_body(response)
        assert "access_token" in data
        assert data["token_type"] == "Bearer"
        assert "expires_in" in data
        assert "user" in data

        # Should NOT have session cookie
        assert not response.cookies

    async def test_login_fallback_to_token_without_sessions(
        self, context: Context, logged_in_user
    ) -> None:
        """Should return token when sessions not enabled."""
        manager = AuthManager()
        request = make_request(
            body=f'{{"email": "{logged_in_user.email}", "password": "password123"}}'.encode()
        )

        response = await manager.login(request, context)

        assert response.status_code == 200
        data = parse_json_body(response)
        assert "access_token" in data


class TestLogout:
    async def test_logout_with_session(
        self, context_with_sessions: Context, logged_in_user
    ) -> None:
        """Should clear session and return logout cookie."""
        manager = AuthManager()

        # Create a session first
        assert context_with_sessions.session_storage is not None
        expires_at = datetime.now(tz=timezone.utc) + timedelta(days=7)
        session = context_with_sessions.session_storage.create_session(
            user_id=logged_in_user.id,
            expires_at=expires_at,
        )

        request = make_request(
            path="/logout",
            cookies={"session_id": session.id},
        )

        response = await manager.logout(request, context_with_sessions)

        assert response.status_code == 200
        data = parse_json_body(response)
        assert data["message"] == "Logged out"

        # Session should be deleted
        assert context_with_sessions.session_storage is not None
        assert context_with_sessions.session_storage.get_session(session.id) is None

        # Should have logout cookie
        assert response.cookies is not None
        assert len(response.cookies) == 1
        cookie = get_cookie(response, "session_id")
        assert cookie.max_age == 0

    async def test_logout_without_sessions(self, context: Context) -> None:
        """Should succeed even without session storage."""
        manager = AuthManager()
        request = make_request(path="/logout")

        response = await manager.logout(request, context)

        assert response.status_code == 200
        data = parse_json_body(response)
        assert data["message"] == "Logged out"


class TestAuthManagerRoutes:
    def test_routes_include_signup_when_enabled(self) -> None:
        """Should include signup route when enabled."""
        manager = AuthManager(enable_signup=True)
        routes = manager.routes

        paths = [r.path for r in routes]
        assert "/signup" in paths
        assert "/login" in paths
        assert "/logout" in paths

    def test_routes_exclude_signup_when_disabled(self) -> None:
        """Should exclude signup route when disabled."""
        manager = AuthManager(enable_signup=False)
        routes = manager.routes

        paths = [r.path for r in routes]
        assert "/signup" not in paths
        assert "/login" in paths
        assert "/logout" in paths
