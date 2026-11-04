"""JSON routes that list and revoke the caller's own sessions.

``AuthRouter`` mounts them next to ``POST /logout`` when ``session_storage`` is
configured. The caller is whoever ``get_user_from_request`` resolves, so a
resolver that also accepts credentials other than Cross Auth sessions (such as
legacy JWTs) works: such a request has no current session.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from cross_web import HTTPRequest
from pydantic import BaseModel, Field

from ._context import Context
from ._route import Route
from ._session import (
    ResolvedSession,
    get_user_session,
    make_clear_cookie,
    make_session_cookie,
    resolve_current_session,
)
from ._storage import SessionRecord, SessionStorage, User
from .exceptions import InvalidCursorError
from .utils._response import Response

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 100


class SessionInfo(BaseModel):
    """One of the caller's active sessions. Never carries its token or hash."""

    id: str
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
    expires_at: datetime
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
        description="How many sessions were revoked, including expired ones "
        "that had not been revoked yet"
    )


def _caller(
    request: HTTPRequest, context: Context
) -> tuple[User, ResolvedSession | None] | None:
    """Return the caller and the Cross Auth session behind the request, if any.

    The session is looked up before the resolver runs: with sliding sessions
    the default resolver would otherwise roll the record forward first, and
    this lookup could no longer tell that the cookie needs rolling too. A
    resolver may accept another credential while the request also carries
    another user's session; every route works on the caller's sessions only,
    so that session never counts as current.
    """
    current = resolve_current_session(
        request, _session_storage(context), context.session_config
    )
    user = context.get_user_from_request(request)
    if user is None:
        return None
    return user, current


def _session_storage(context: Context) -> SessionStorage:
    assert context.session_storage is not None
    return context.session_storage


def _unauthorized() -> Response:
    return Response.error(
        "unauthorized", error_description="Not logged in", status_code=401
    )


def _json(model: BaseModel) -> Response:
    return Response(
        status_code=200,
        body=model.model_dump_json(),
        headers={"Content-Type": "application/json"},
    )


def _roll_cookie(
    response: Response, current: ResolvedSession | None, context: Context
) -> Response:
    """Re-send a sliding session's cookie that this request rolled forward."""
    if current is not None and current.source == "cookie" and current.refreshed:
        response.cookies = [
            *(response.cookies or []),
            make_session_cookie(current.token, context.session_config),
        ]
    return response


def _parse_limit(value: str | None) -> int | None:
    if value is None:
        return DEFAULT_PAGE_SIZE
    try:
        limit = int(value)
    except ValueError:
        return None
    return limit if 1 <= limit <= MAX_PAGE_SIZE else None


def _session_info(record: SessionRecord, *, current_id: str | None) -> SessionInfo:
    return SessionInfo(
        id=str(record.id),
        client_id=record.client_id,
        client_name=record.client_name,
        user_agent=record.user_agent,
        ip=record.ip,
        login_method=record.login_method,
        created_at=record.created_at,
        expires_at=record.expires_at,
        current=str(record.id) == current_id,
    )


def list_sessions(request: HTTPRequest, context: Context) -> Response:
    """GET /sessions — the caller's active sessions, newest first."""
    caller = _caller(request, context)
    if caller is None:
        return _unauthorized()
    user, current = caller

    limit = _parse_limit(request.query_params.get("limit"))
    if limit is None:
        return Response.error(
            "invalid_request",
            error_description=f"limit must be an integer from 1 to {MAX_PAGE_SIZE}",
        )
    try:
        result = _session_storage(context).list_for_user(
            user.id,
            now=datetime.now(tz=timezone.utc),
            status="active",
            order_by="created_at_desc",
            limit=limit,
            cursor=request.query_params.get("cursor"),
        )
    except InvalidCursorError:
        return Response.error("invalid_request", error_description="Invalid cursor")

    current_id = str(current.record.id) if current is not None else None
    session_list = SessionList(
        sessions=[
            _session_info(record, current_id=current_id) for record in result.records
        ],
        next_cursor=result.next_cursor,
    )
    return _roll_cookie(_json(session_list), current, context)


def revoke_session(request: HTTPRequest, context: Context) -> Response:
    """DELETE /sessions/{session_id} — revoke one of the caller's sessions.

    Another user's session answers 404 like an unknown id. Revoking the
    current cookie session also clears the cookie, as ``/logout`` does.
    """
    caller = _caller(request, context)
    if caller is None:
        return _unauthorized()
    user, current = caller

    session_storage = _session_storage(context)
    session = get_user_session(
        request.path_params["session_id"], session_storage, user_id=user.id
    )
    if session is None:
        return Response.error(
            "session_not_found",
            error_description="Session not found",
            status_code=404,
        )
    session_storage.revoke(session.id, revoked_at=datetime.now(tz=timezone.utc))

    response = Response(status_code=204)
    if current is not None and str(current.record.id) == str(session.id):
        if current.source == "cookie":
            response.cookies = [make_clear_cookie(context.session_config)]
        return response
    return _roll_cookie(response, current, context)


def revoke_other_sessions(request: HTTPRequest, context: Context) -> Response:
    """POST /sessions/revoke-others — revoke all the caller's other sessions.

    Without a current session (the resolver accepted another credential),
    every session of the caller is another one, so all of them are revoked.
    """
    caller = _caller(request, context)
    if caller is None:
        return _unauthorized()
    user, current = caller

    revoked = _session_storage(context).revoke_all_for_user(
        user.id,
        revoked_at=datetime.now(tz=timezone.utc),
        except_session_id=current.record.id if current is not None else None,
    )
    return _roll_cookie(_json(RevokedSessions(revoked=revoked)), current, context)


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
            summary="List the caller's active sessions",
            openapi={
                "parameters": [
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
                    {"400": "Invalid limit or cursor", "401": "Not logged in"}
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
