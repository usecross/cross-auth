"""Tests for session management endpoints."""

import json
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock

import pytest
from cross_web import AsyncHTTPRequest, Response

from cross_auth._context import Context
from cross_auth._session import SessionManager

pytestmark = pytest.mark.asyncio


def parse_json_body(response: Response) -> dict[str, Any]:
    """Parse JSON response body, asserting it's not None."""
    assert response.body is not None, "Response body should not be None"
    return json.loads(response.body)


def get_cookie(response: Response, name: str):
    """Get a cookie from the response by name."""
    assert response.cookies is not None, "Response should have cookies"
    for cookie in response.cookies:
        if cookie.name == name:
            return cookie
    raise AssertionError(f"Cookie '{name}' not found")


def make_request(
    path: str = "/session",
    cookies: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
) -> AsyncHTTPRequest:
    """Create a mock AsyncHTTPRequest for testing."""
    request = MagicMock(spec=AsyncHTTPRequest)
    # request.url should be a string (as per cross_web spec)
    request.url = f"http://localhost{path}"
    request.cookies = cookies or {}
    request.headers = headers or {}
    return request


class TestGetCurrentSession:
    async def test_returns_error_when_sessions_not_enabled(
        self, context: Context
    ) -> None:
        """Should return error if session storage not configured."""
        manager = SessionManager()
        request = make_request()

        response = await manager.get_current_session(request, context)

        assert response.status_code == 400
        data = parse_json_body(response)
        assert data["error"] == "session_not_enabled"

    async def test_returns_401_when_no_session_cookie(
        self, context_with_sessions: Context
    ) -> None:
        """Should return 401 if no session cookie provided."""
        manager = SessionManager()
        request = make_request()

        response = await manager.get_current_session(request, context_with_sessions)

        assert response.status_code == 401
        data = parse_json_body(response)
        assert data["error"] == "unauthorized"

    async def test_returns_401_for_invalid_session(
        self, context_with_sessions: Context
    ) -> None:
        """Should return 401 if session ID is invalid."""
        manager = SessionManager()
        request = make_request(cookies={"session_id": "invalid-session-id"})

        response = await manager.get_current_session(request, context_with_sessions)

        assert response.status_code == 401
        data = parse_json_body(response)
        assert data["error"] == "unauthorized"

    async def test_returns_session_info_for_valid_session(
        self, context_with_sessions: Context, logged_in_user
    ) -> None:
        """Should return session and user info for valid session."""
        manager = SessionManager()
        assert context_with_sessions.session_storage is not None

        # Create a session first
        expires_at = datetime.now(tz=timezone.utc) + timedelta(days=7)
        session = context_with_sessions.session_storage.create_session(
            user_id=logged_in_user.id,
            expires_at=expires_at,
            ip_address="127.0.0.1",
            user_agent="TestBrowser/1.0",
        )

        request = make_request(cookies={"session_id": session.id})

        response = await manager.get_current_session(request, context_with_sessions)

        assert response.status_code == 200
        data = parse_json_body(response)
        assert data["session"]["id"] == session.id
        assert data["user"]["id"] == logged_in_user.id
        assert data["user"]["email"] == logged_in_user.email


class TestLogout:
    async def test_returns_error_when_sessions_not_enabled(
        self, context: Context
    ) -> None:
        """Should return error if session storage not configured."""
        manager = SessionManager()
        request = make_request()

        response = await manager.logout(request, context)

        assert response.status_code == 400
        data = parse_json_body(response)
        assert data["error"] == "session_not_enabled"

    async def test_logout_deletes_session(
        self, context_with_sessions: Context, logged_in_user
    ) -> None:
        """Should delete session and return logout cookie."""
        manager = SessionManager()
        assert context_with_sessions.session_storage is not None

        # Create a session first
        expires_at = datetime.now(tz=timezone.utc) + timedelta(days=7)
        session = context_with_sessions.session_storage.create_session(
            user_id=logged_in_user.id,
            expires_at=expires_at,
        )

        request = make_request(cookies={"session_id": session.id})

        response = await manager.logout(request, context_with_sessions)

        assert response.status_code == 200
        data = parse_json_body(response)
        assert data["message"] == "Logged out"

        # Session should be deleted
        assert context_with_sessions.session_storage is not None
        assert context_with_sessions.session_storage.get_session(session.id) is None

        # Response should have logout cookie
        assert response.cookies is not None
        assert len(response.cookies) == 1
        cookie = get_cookie(response, "session_id")
        assert cookie.max_age == 0

    async def test_logout_succeeds_even_without_session(
        self, context_with_sessions: Context
    ) -> None:
        """Should succeed even if not authenticated (to prevent info leakage)."""
        manager = SessionManager()
        request = make_request()

        response = await manager.logout(request, context_with_sessions)

        assert response.status_code == 200
        data = parse_json_body(response)
        assert data["message"] == "Logged out"


class TestListSessions:
    async def test_returns_error_when_sessions_not_enabled(
        self, context: Context
    ) -> None:
        """Should return error if session storage not configured."""
        manager = SessionManager()
        request = make_request()

        response = await manager.list_sessions(request, context)

        assert response.status_code == 400
        data = parse_json_body(response)
        assert data["error"] == "session_not_enabled"

    async def test_returns_401_when_not_authenticated(
        self, context_with_sessions: Context
    ) -> None:
        """Should return 401 if not authenticated."""
        manager = SessionManager()
        request = make_request()

        response = await manager.list_sessions(request, context_with_sessions)

        assert response.status_code == 401

    async def test_returns_all_user_sessions(
        self, context_with_sessions: Context, logged_in_user
    ) -> None:
        """Should return all sessions for the authenticated user."""
        manager = SessionManager()
        assert context_with_sessions.session_storage is not None

        # Create multiple sessions
        expires_at = datetime.now(tz=timezone.utc) + timedelta(days=7)
        session1 = context_with_sessions.session_storage.create_session(
            user_id=logged_in_user.id,
            expires_at=expires_at,
            ip_address="127.0.0.1",
            user_agent="Browser1",
        )
        session2 = context_with_sessions.session_storage.create_session(
            user_id=logged_in_user.id,
            expires_at=expires_at,
            ip_address="192.168.1.1",
            user_agent="Browser2",
        )

        request = make_request(cookies={"session_id": session1.id})

        response = await manager.list_sessions(request, context_with_sessions)

        assert response.status_code == 200
        data = parse_json_body(response)
        assert len(data["sessions"]) == 2

        # Current session should be marked
        session_ids = {s["id"]: s for s in data["sessions"]}
        assert session_ids[session1.id]["current"] is True
        assert session_ids[session2.id]["current"] is False


class TestRevokeSession:
    async def test_returns_error_when_sessions_not_enabled(
        self, context: Context
    ) -> None:
        """Should return error if session storage not configured."""
        manager = SessionManager()
        request = make_request(path="/sessions/some-id")

        response = await manager.revoke_session(request, context)

        assert response.status_code == 400
        data = parse_json_body(response)
        assert data["error"] == "session_not_enabled"

    async def test_returns_401_when_not_authenticated(
        self, context_with_sessions: Context
    ) -> None:
        """Should return 401 if not authenticated."""
        manager = SessionManager()
        request = make_request(path="/sessions/some-id")

        response = await manager.revoke_session(request, context_with_sessions)

        assert response.status_code == 401

    async def test_returns_404_for_nonexistent_session(
        self, context_with_sessions: Context, logged_in_user
    ) -> None:
        """Should return 404 if session doesn't exist."""
        manager = SessionManager()
        assert context_with_sessions.session_storage is not None

        # Create auth session
        expires_at = datetime.now(tz=timezone.utc) + timedelta(days=7)
        auth_session = context_with_sessions.session_storage.create_session(
            user_id=logged_in_user.id,
            expires_at=expires_at,
        )

        request = make_request(
            path="/sessions/nonexistent-id",
            cookies={"session_id": auth_session.id},
        )

        response = await manager.revoke_session(request, context_with_sessions)

        assert response.status_code == 404

    async def test_revokes_user_session(
        self, context_with_sessions: Context, logged_in_user
    ) -> None:
        """Should revoke the specified session."""
        manager = SessionManager()
        assert context_with_sessions.session_storage is not None

        # Create two sessions
        expires_at = datetime.now(tz=timezone.utc) + timedelta(days=7)
        session1 = context_with_sessions.session_storage.create_session(
            user_id=logged_in_user.id,
            expires_at=expires_at,
        )
        session2 = context_with_sessions.session_storage.create_session(
            user_id=logged_in_user.id,
            expires_at=expires_at,
        )

        # Revoke session2 while authenticated with session1
        request = make_request(
            path=f"/sessions/{session2.id}",
            cookies={"session_id": session1.id},
        )

        response = await manager.revoke_session(request, context_with_sessions)

        assert response.status_code == 200

        # Session2 should be deleted
        assert context_with_sessions.session_storage.get_session(session2.id) is None

        # Session1 should still exist
        assert (
            context_with_sessions.session_storage.get_session(session1.id) is not None
        )

    async def test_cannot_revoke_other_users_session(
        self, context_with_sessions: Context, accounts_storage, logged_in_user
    ) -> None:
        """Should return 403 when trying to revoke another user's session."""
        manager = SessionManager()
        assert context_with_sessions.session_storage is not None

        # Create another user
        other_user = accounts_storage.create_user_with_password(
            email="other@example.com",
            hashed_password="hash",
        )

        # Create sessions for both users
        expires_at = datetime.now(tz=timezone.utc) + timedelta(days=7)
        my_session = context_with_sessions.session_storage.create_session(
            user_id=logged_in_user.id,
            expires_at=expires_at,
        )
        other_session = context_with_sessions.session_storage.create_session(
            user_id=other_user.id,
            expires_at=expires_at,
        )

        # Try to revoke other user's session
        request = make_request(
            path=f"/sessions/{other_session.id}",
            cookies={"session_id": my_session.id},
        )

        response = await manager.revoke_session(request, context_with_sessions)

        assert response.status_code == 403
        data = parse_json_body(response)
        assert data["error"] == "forbidden"
