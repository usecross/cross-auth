"""JSON routes that list and revoke the caller's own sessions.

``AuthRouter`` mounts them next to ``POST /logout`` when ``session_storage`` is
configured. Like ``/logout`` they act on the session behind the request
(cookie first, then bearer token) and on that session's user.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from functools import wraps
from typing import Any

from cross_web import HTTPRequest
from pydantic import BaseModel, Field

from ._context import Context
from ._login import revoke_user_session, revoke_user_sessions
from ._route import Route
from ._session import (
    ResolvedSession,
    get_user_session,
    make_clear_cookie,
    make_session_cookie,
)
from ._storage import SessionRecord, SessionStatus, SessionStorage, session_status
from .exceptions import CrossAuthException, InvalidCursorError
from .utils._response import Response

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 100
STATUS_FILTERS: dict[str, SessionStatus | None] = {
    "active": "active",
    "expired": "expired",
    "revoked": "revoked",
    "all": None,
}


class SessionInfo(BaseModel):
    """One of the caller's sessions. Never carries its token or hash."""

    id: str
    status: SessionStatus
    client_id: str | None = Field(
        description="The OAuth client that started the session, if any"
    )
    client_name: str | None
    user_agent: str | None
    ip: str | None
    login_method: str | None = Field(
        description='How the user signed in: a provider id, "password", or '
        "what the application recorded"
    )
    created_at: datetime
    last_active_at: datetime | None = Field(
        description="When the session was last used: its sign-in, or its latest "
        "sliding refresh (recorded at most once per update_age)"
    )
    expires_at: datetime
    revoked_at: datetime | None
    current: bool = Field(
        description="Whether this is the session that authenticated the request"
    )


class SessionList(BaseModel):
    sessions: list[SessionInfo] = Field(description="Newest first")
    next_cursor: str | None = Field(
        description="Pass as `cursor` to fetch the next page; null on the last page"
    )


class RevokedSessions(BaseModel):
    revoked: int = Field(
        description="How many active sessions were revoked; expired ones stay expired"
    )


def _session_storage(context: Context) -> SessionStorage:
    assert context.session_storage is not None
    return context.session_storage


def _json(model: BaseModel) -> Response:
    return Response(
        status_code=200,
        body=model.model_dump_json(),
        headers={"Content-Type": "application/json"},
    )


def _session_endpoint(
    handler: Callable[[HTTPRequest, Context, ResolvedSession], Response],
) -> Callable[[HTTPRequest, Context], Response]:
    @wraps(handler)
    def endpoint(request: HTTPRequest, context: Context) -> Response:
        # Like other session uses, a user user_can_authenticate refuses
        # cannot list or revoke sessions; /logout still ends their own.
        try:
            current = context.resolve_current_session(request)
        except CrossAuthException as e:
            return _hook_error(e)
        if current is None:
            return Response.error(
                "unauthorized", error_description="Not logged in", status_code=401
            )
        response = handler(request, context, current)
        if current.source == "cookie" and current.refreshed:
            cookie = make_session_cookie(current.token, context.session_config)
            if not any(
                existing.name == cookie.name for existing in response.cookies or []
            ):
                response.cookies = [*(response.cookies or []), cookie]
        return response

    return endpoint


def _parse_limit(value: str | None) -> int | None:
    if value is None:
        return DEFAULT_PAGE_SIZE
    try:
        limit = int(value)
    except ValueError:
        return None
    return limit if 1 <= limit <= MAX_PAGE_SIZE else None


def _session_info(
    record: SessionRecord, *, current_id: str, now: datetime
) -> SessionInfo:
    return SessionInfo(
        id=str(record.id),
        status=session_status(record, now=now),
        client_id=record.client_id,
        client_name=record.client_name,
        user_agent=record.user_agent,
        ip=record.ip,
        login_method=record.login_method,
        created_at=record.created_at,
        last_active_at=record.last_active_at,
        expires_at=record.expires_at,
        revoked_at=record.revoked_at,
        current=str(record.id) == current_id,
    )


def _hook_error(error: CrossAuthException) -> Response:
    return Response.error(
        error.error,
        error_description=error.error_description,
        status_code=error.status_code,
    )


@_session_endpoint
def list_sessions(
    request: HTTPRequest, context: Context, current: ResolvedSession
) -> Response:
    """GET /sessions — the caller's sessions, newest first.

    ``?status=`` picks ``active`` (the default), ``expired``, ``revoked`` or
    ``all`` of them.
    """
    status = request.query_params.get("status", "active")
    if status not in STATUS_FILTERS:
        error = Response.error(
            "invalid_request",
            error_description="status must be one of " + ", ".join(STATUS_FILTERS),
        )
        return error
    limit = _parse_limit(request.query_params.get("limit"))
    if limit is None:
        error = Response.error(
            "invalid_request",
            error_description=f"limit must be an integer from 1 to {MAX_PAGE_SIZE}",
        )
        return error
    now = datetime.now(tz=timezone.utc)
    try:
        result = _session_storage(context).list_for_user(
            current.record.user_id,
            now=now,
            status=STATUS_FILTERS[status],
            order_by="created_at_desc",
            limit=limit,
            cursor=request.query_params.get("cursor"),
        )
    except InvalidCursorError:
        error = Response.error("invalid_request", error_description="Invalid cursor")
        return error

    current_id = str(current.record.id)
    session_list = SessionList(
        sessions=[
            _session_info(record, current_id=current_id, now=now)
            for record in result.records
        ],
        next_cursor=result.next_cursor,
    )
    return _json(session_list)


@_session_endpoint
def revoke_session(
    request: HTTPRequest, context: Context, current: ResolvedSession
) -> Response:
    """DELETE /sessions/{session_id} — revoke one of the caller's sessions.

    Another user's session answers 404 like an unknown id. Revoking the
    current cookie session also clears the cookie, as ``/logout`` does.
    """
    session_storage = _session_storage(context)
    session = get_user_session(
        request.path_params["session_id"],
        session_storage,
        user_id=current.record.user_id,
    )
    if session is None:
        error = Response.error(
            "session_not_found",
            error_description="Session not found",
            status_code=404,
        )
        return error
    try:
        revoke_user_session(
            session,
            hooks=context.hooks,
            session_storage=session_storage,
            request=request,
        )
    except CrossAuthException as e:
        return _hook_error(e)

    response = Response(status_code=204)
    if str(current.record.id) == str(session.id) and current.source == "cookie":
        response.cookies = [make_clear_cookie(context.session_config)]
    return response


@_session_endpoint
def revoke_other_sessions(
    request: HTTPRequest, context: Context, current: ResolvedSession
) -> Response:
    """POST /sessions/revoke-others — revoke all the caller's other sessions."""
    try:
        revoked = revoke_user_sessions(
            current.record.user_id,
            keep_session_id=current.record.id,
            hooks=context.hooks,
            session_storage=_session_storage(context),
            request=request,
        )
    except CrossAuthException as e:
        return _hook_error(e)
    return _json(RevokedSessions(revoked=revoked))


def _responses(descriptions: dict[str, str]) -> dict[str, Any]:
    return {
        "responses": {
            status: {"description": description}
            for status, description in descriptions.items()
        }
    }


def session_routes() -> list[Route]:
    return [
        Route(
            path="/sessions",
            methods=["GET"],
            function=list_sessions,
            response_model=SessionList,
            operation_id="list_sessions",
            summary="List the caller's sessions",
            openapi={
                "parameters": [
                    {
                        "name": "status",
                        "in": "query",
                        "required": False,
                        "schema": {
                            "type": "string",
                            "enum": list(STATUS_FILTERS),
                            "default": "active",
                            "title": "Status",
                        },
                        "description": "Which sessions to list",
                    },
                    {
                        "name": "limit",
                        "in": "query",
                        "required": False,
                        "schema": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": MAX_PAGE_SIZE,
                            "default": DEFAULT_PAGE_SIZE,
                            "title": "Limit",
                        },
                    },
                    {
                        "name": "cursor",
                        "in": "query",
                        "required": False,
                        "schema": {"type": "string", "title": "Cursor"},
                        "description": "The next_cursor of the previous page",
                    },
                ],
                **_responses(
                    {"400": "Invalid status, limit or cursor", "401": "Not logged in"}
                ),
            },
        ),
        Route(
            path="/sessions/revoke-others",
            methods=["POST"],
            function=revoke_other_sessions,
            response_model=RevokedSessions,
            operation_id="revoke_other_sessions",
            summary="Revoke the caller's other sessions",
            openapi=_responses({"401": "Not logged in"}),
        ),
        Route(
            path="/sessions/{session_id}",
            methods=["DELETE"],
            function=revoke_session,
            status_code=204,
            operation_id="revoke_session",
            summary="Revoke one of the caller's sessions",
            path_parameters=[
                {
                    "name": "session_id",
                    "in": "path",
                    "required": True,
                    "schema": {"type": "string", "title": "Session Id"},
                }
            ],
            openapi=_responses(
                {
                    "401": "Not logged in",
                    "404": "No session with this id belongs to the caller",
                }
            ),
        ),
    ]
