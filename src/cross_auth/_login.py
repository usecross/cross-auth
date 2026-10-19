from __future__ import annotations

from cross_web import Response

from ._session import (
    SessionConfig,
    SessionMetadata,
    create_session,
    make_session_cookie,
    resolve_config,
)
from ._storage import SessionStorage
from .hooks import AfterLoginEvent, BeforeLoginEvent, HookRegistry


def login_with_session(
    user_id: str,
    *,
    response: Response,
    hooks: HookRegistry,
    session_storage: SessionStorage,
    session_config: SessionConfig | None,
    metadata: SessionMetadata | None = None,
) -> Response:
    """Run the ``login`` hooks around one new session and its cookie.

    Returns the hook response with the session cookie appended; adapters
    decide how to send it and how to surface hook exceptions.
    """
    event = hooks.run_before(
        "login",
        BeforeLoginEvent(user_id=user_id, response=response),
    )
    resolved = resolve_config(session_config)
    session_token, session_record = create_session(
        event.user_id,
        session_storage,
        max_age=resolved["max_age"],
        metadata=metadata,
        token_hasher=resolved["token_hasher"],
    )
    cookie = make_session_cookie(session_token, session_config)

    if event.response.cookies is None:
        event.response.cookies = []
    event.response.cookies.append(cookie)

    hooks.run_after(
        "login",
        AfterLoginEvent(
            user_id=event.user_id,
            response=event.response,
            session_record=session_record,
            cookie=cookie,
        ),
    )

    return event.response
