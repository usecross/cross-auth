"""Session management module for cross-auth.

Provides endpoints for session CRUD operations:
- GET /session - Get current session info
- DELETE /session - Logout (delete current session)
- GET /sessions - List all user sessions
- DELETE /sessions/{session_id} - Revoke a specific session
"""

import json
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from cross_web import AsyncHTTPRequest

from ._config import SessionConfig
from ._context import Context
from ._route import Route
from .utils._response import Response


class SessionManager:
    """Manager for session-based authentication routes."""

    def __init__(self, config: SessionConfig | None = None):
        self.config = config or {}

    async def get_current_session(
        self, request: AsyncHTTPRequest, context: Context
    ) -> Response:
        """Get the current session info.

        Returns 401 if not authenticated via session.
        """
        if not context.session_enabled:
            return Response.error(
                "session_not_enabled",
                error_description="Session-based authentication is not enabled",
                status_code=400,
            )

        session = context.get_session_from_request(request)

        if not session:
            return Response.error(
                "unauthorized",
                error_description="Not authenticated",
                status_code=401,
            )

        # Get user info
        user = context.accounts_storage.find_user_by_id(session.user_id)

        if not user:
            # Session exists but user doesn't - this shouldn't happen normally
            # Delete the orphan session
            if context.session_storage:
                context.session_storage.delete_session(session.id)
            return Response.error(
                "unauthorized",
                error_description="Session invalid",
                status_code=401,
            )

        # Check if session needs refresh (sliding sessions)
        cookies = []
        if context.should_refresh_session(session) and context.session_storage:
            expires_in = int(context.get_session_config("expires_in") or 604800)
            new_expiry = datetime.now(tz=timezone.utc) + timedelta(seconds=expires_in)
            context.session_storage.update_session_expiry(session.id, new_expiry)
            cookies.append(context.create_session_cookie(session, new_expiry))

        response_data = {
            "session": {
                "id": session.id,
                "created_at": session.created_at.isoformat(),
                "expires_at": session.expires_at.isoformat(),
                "ip_address": session.ip_address,
                "user_agent": session.user_agent,
            },
            "user": {
                "id": str(user.id),
                "email": user.email,
                "email_verified": user.email_verified,
            },
        }

        return Response(
            status_code=200,
            body=json.dumps(response_data),
            headers={"Content-Type": "application/json"},
            cookies=cookies,
        )

    async def logout(self, request: AsyncHTTPRequest, context: Context) -> Response:
        """Logout by deleting the current session.

        Always returns success (even if not authenticated) to prevent
        information leakage about session state.
        """
        if not context.session_enabled or not context.session_storage:
            return Response.error(
                "session_not_enabled",
                error_description="Session-based authentication is not enabled",
                status_code=400,
            )

        session = context.get_session_from_request(request)

        if session:
            context.session_storage.delete_session(session.id)

        # Always return logout cookie to clear the session on client
        logout_cookie = context.create_logout_cookie()

        return Response(
            status_code=200,
            body=json.dumps({"message": "Logged out"}),
            headers={"Content-Type": "application/json"},
            cookies=[logout_cookie],
        )

    async def list_sessions(
        self, request: AsyncHTTPRequest, context: Context
    ) -> Response:
        """List all sessions for the current user.

        Requires authentication.
        """
        if not context.session_enabled or not context.session_storage:
            return Response.error(
                "session_not_enabled",
                error_description="Session-based authentication is not enabled",
                status_code=400,
            )

        # Try to get user from session first, then fall back to token-based auth
        session = context.get_session_from_request(request)
        user = None

        if session:
            user = context.accounts_storage.find_user_by_id(session.user_id)
        else:
            # Fall back to token-based auth
            user = context.get_user_from_request(request)

        if not user:
            return Response.error(
                "unauthorized",
                error_description="Not authenticated",
                status_code=401,
            )

        sessions = context.session_storage.list_user_sessions(user.id)
        current_session_id = session.id if session else None

        sessions_data = [
            {
                "id": s.id,
                "created_at": s.created_at.isoformat(),
                "expires_at": s.expires_at.isoformat(),
                "ip_address": s.ip_address,
                "user_agent": s.user_agent,
                "current": s.id == current_session_id,
            }
            for s in sessions
        ]

        return Response(
            status_code=200,
            body=json.dumps({"sessions": sessions_data}),
            headers={"Content-Type": "application/json"},
        )

    async def revoke_session(
        self, request: AsyncHTTPRequest, context: Context
    ) -> Response:
        """Revoke a specific session by ID.

        Requires authentication. Users can only revoke their own sessions.
        """
        if not context.session_enabled or not context.session_storage:
            return Response.error(
                "session_not_enabled",
                error_description="Session-based authentication is not enabled",
                status_code=400,
            )

        # Try to get user from session first, then fall back to token-based auth
        current_session = context.get_session_from_request(request)
        user = None

        if current_session:
            user = context.accounts_storage.find_user_by_id(current_session.user_id)
        else:
            # Fall back to token-based auth
            user = context.get_user_from_request(request)

        if not user:
            return Response.error(
                "unauthorized",
                error_description="Not authenticated",
                status_code=401,
            )

        # Extract session_id from path
        # Path format: /sessions/{session_id}
        parsed_url = urlparse(str(request.url))
        session_id = parsed_url.path.split("/")[-1]

        if not session_id:
            return Response.error(
                "invalid_request",
                error_description="Session ID is required",
                status_code=400,
            )

        # Verify the session belongs to this user
        target_session = context.session_storage.get_session(session_id)

        if not target_session:
            return Response.error(
                "not_found",
                error_description="Session not found",
                status_code=404,
            )

        if str(target_session.user_id) != str(user.id):
            return Response.error(
                "forbidden",
                error_description="Cannot revoke another user's session",
                status_code=403,
            )

        context.session_storage.delete_session(session_id)

        # If user is revoking their own current session, include logout cookie
        cookies = []
        if current_session and current_session.id == session_id:
            cookies.append(context.create_logout_cookie())

        return Response(
            status_code=200,
            body=json.dumps({"message": "Session revoked"}),
            headers={"Content-Type": "application/json"},
            cookies=cookies,
        )

    @property
    def routes(self) -> list[Route]:
        """Return the session management routes."""
        return [
            Route(
                path="/session",
                methods=["GET"],
                function=self.get_current_session,
                operation_id="get_current_session",
                summary="Get current session info",
            ),
            Route(
                path="/session",
                methods=["DELETE"],
                function=self.logout,
                operation_id="logout_session",
                summary="Logout (delete current session)",
            ),
            Route(
                path="/sessions",
                methods=["GET"],
                function=self.list_sessions,
                operation_id="list_sessions",
                summary="List all user sessions",
            ),
            Route(
                path="/sessions/{session_id}",
                methods=["DELETE"],
                function=self.revoke_session,
                operation_id="revoke_session",
                summary="Revoke a specific session",
            ),
        ]
