from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar

from cross_web import Response

from ._session import (
    SessionConfig,
    SessionMetadata,
    _build_cookie,
    create_session,
    resolve_config,
)
from ._storage import SessionRecord, SessionStorage
from .hooks import AfterLoginEvent, BeforeLoginEvent, HookRegistry

_IssuedT = TypeVar("_IssuedT")


def run_login(
    event: BeforeLoginEvent,
    *,
    hooks: HookRegistry,
    issue: Callable[[BeforeLoginEvent], tuple[_IssuedT, SessionRecord | None]],
) -> tuple[_IssuedT, BeforeLoginEvent]:
    """Run one ``login`` lifecycle around issuing a credential.

    ``issue`` creates the credential from the approved event and returns it
    with the Cross Auth session it created, if any. Hook exceptions propagate:
    a before-hook failure issues nothing; an after-hook failure leaves the
    issued credential in place.
    """
    approved = hooks.run_before("login", event)
    _check_login_rewrite(event, approved)

    issued, session_record = issue(approved)

    hooks.run_after(
        "login",
        AfterLoginEvent(
            user_id=approved.user_id,
            credential=approved.credential,
            session_record=session_record,
            response=approved.response,
        ),
    )
    return issued, approved


def _check_login_rewrite(
    original: BeforeLoginEvent, approved: BeforeLoginEvent
) -> None:
    if approved.user_id != original.user_id:
        raise ValueError("login before hooks cannot change user_id")
    if approved.credential != original.credential:
        raise ValueError("login before hooks cannot change credential")
    if (approved.response is None) != (original.response is None):
        raise ValueError("login before hooks cannot add or remove the response")
    if original.max_age is None:
        if approved.max_age is not None or approved.metadata is not None:
            raise ValueError(
                "login before hooks cannot set max_age or metadata for "
                "credentials minted by a token_issuer"
            )
    elif approved.max_age is None:
        raise ValueError("login before hooks must keep a session max_age")


def login_with_session(
    user_id: str,
    *,
    response: Response,
    hooks: HookRegistry,
    session_storage: SessionStorage,
    session_config: SessionConfig | None,
    metadata: SessionMetadata | None = None,
) -> Response:
    """Log in with one new session and its cookie appended to ``response``.

    Returns the hook response; adapters decide how to send it and how to
    surface hook exceptions.
    """
    resolved = resolve_config(session_config)

    def issue(event: BeforeLoginEvent) -> tuple[Response, SessionRecord]:
        assert event.response is not None
        assert event.max_age is not None
        session_token, session_record = create_session(
            event.user_id,
            session_storage,
            max_age=event.max_age,
            metadata=event.metadata,
            token_hasher=resolved["token_hasher"],
        )
        if event.response.cookies is None:
            event.response.cookies = []
        event.response.cookies.append(
            _build_cookie(session_token, event.max_age, resolved)
        )
        return event.response, session_record

    hook_response, _ = run_login(
        BeforeLoginEvent(
            user_id=user_id,
            credential="cookie",
            max_age=resolved["max_age"],
            metadata=metadata,
            response=response,
        ),
        hooks=hooks,
        issue=issue,
    )
    return hook_response


def issue_bearer_session(
    user_id: str,
    *,
    hooks: HookRegistry,
    session_storage: SessionStorage,
    session_config: SessionConfig | None,
    max_age: int | None = None,
    metadata: SessionMetadata | None = None,
) -> tuple[str, SessionRecord, int]:
    """Log in with one new session; return its bearer token, record and max_age."""
    resolved = resolve_config(session_config)

    def issue(
        event: BeforeLoginEvent,
    ) -> tuple[tuple[str, SessionRecord], SessionRecord]:
        assert event.max_age is not None
        session_token, session_record = create_session(
            event.user_id,
            session_storage,
            max_age=event.max_age,
            metadata=event.metadata,
            token_hasher=resolved["token_hasher"],
        )
        return (session_token, session_record), session_record

    (session_token, session_record), approved = run_login(
        BeforeLoginEvent(
            user_id=user_id,
            credential="bearer",
            max_age=max_age if max_age is not None else resolved["max_age"],
            metadata=metadata,
        ),
        hooks=hooks,
        issue=issue,
    )
    assert approved.max_age is not None
    return session_token, session_record, approved.max_age
