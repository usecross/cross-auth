from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from typing import Protocol, TypeVar

from cross_web import HTTPRequest, Response

from ._session import (
    SessionConfig,
    SessionMetadata,
    _build_cookie,
    create_session,
    get_bearer_token,
    hash_session_token,
    make_clear_cookie,
    resolve_config,
)
from ._storage import CommitCallback, SessionRecord, SessionStorage, User
from .hooks import (
    AfterLoginEvent,
    AfterLogoutEvent,
    BeforeLoginEvent,
    BeforeLogoutEvent,
    HookRegistry,
)

_IssuedT = TypeVar("_IssuedT")


def run_login(
    event: BeforeLoginEvent,
    *,
    hooks: HookRegistry,
    issue: Callable[[BeforeLoginEvent], tuple[_IssuedT, SessionRecord | None]],
    on_commit: Callable[[CommitCallback], None],
) -> tuple[_IssuedT, BeforeLoginEvent]:
    """Run one ``login`` lifecycle around issuing a credential.

    ``issue`` creates the credential from the approved event and returns it
    with the Cross Auth session it created, if any. ``on_commit`` belongs to
    whatever stores the credential and schedules the after hook once it is
    committed. Hook exceptions propagate: a before-hook failure issues nothing;
    an after-hook failure leaves the issued credential in place.
    """
    approved = hooks.run_before("login", event)
    _check_login_rewrite(event, approved)

    issued, session_record = issue(approved)

    after_event = AfterLoginEvent(
        user_id=approved.user_id,
        credential=approved.credential,
        session_record=session_record,
        response=approved.response,
    )
    on_commit(lambda: hooks.run_after("login", after_event))
    return issued, approved


class BrowserLogin(Protocol):
    """Logs a browser in with a session the web framework owns.

    Browser sign-in uses this in place of a Cross Auth cookie session once the
    provider identity is verified and the user's account changes committed.
    """

    def login(self, user: User, *, response: Response) -> Response:
        """Log ``user`` in through ``run_login`` and return the response.

        Raise ``CrossAuthException`` to refuse a user the framework does not
        allow to sign in.
        """
        ...

    def on_commit(self, callback: CommitCallback) -> None:
        """Run callback once the login's session write is committed."""
        ...


def run_now(callback: CommitCallback) -> None:
    """Commit scheduler for work that is already durable when it returns."""
    callback()


def require_immediate_commit(
    on_commit: Callable[[CommitCallback], None], message: str
) -> None:
    """Raise unless ``on_commit`` runs callbacks at once.

    A storage that defers them has joined an application transaction, so its
    writes are not committed yet. Flows whose credential or response cannot
    wait for that commit call this before writing anything.
    """
    committed = False

    def mark_committed() -> None:
        nonlocal committed
        committed = True

    on_commit(mark_committed)
    if not committed:
        raise RuntimeError(message)


# Cookie login and logout hand their after hooks the response, which the
# framework adapter copies before an application transaction could commit.
COOKIE_SESSION_COMMIT_ERROR = (
    "{action} needs a session storage whose writes commit before it returns; "
    "do not run it inside an application transaction"
)


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
                "credentials minted by a token_issuer or the web framework"
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
    require_immediate_commit(
        session_storage.on_commit,
        COOKIE_SESSION_COMMIT_ERROR.format(action="Cookie login"),
    )
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
        on_commit=session_storage.on_commit,
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
        on_commit=session_storage.on_commit,
    )
    assert approved.max_age is not None
    return session_token, session_record, approved.max_age


def logout_session(
    request: HTTPRequest,
    *,
    response: Response,
    hooks: HookRegistry,
    session_storage: SessionStorage,
    session_config: SessionConfig | None,
) -> Response:
    """Revoke the request's session and clear the session cookie on ``response``.

    The session token comes from the session cookie, then from an
    ``Authorization: Bearer`` header, and ``logout`` before hooks may replace
    it. A missing, unknown, expired or already revoked token revokes nothing.
    Returns the hook response; adapters decide how to send it and how to
    surface hook exceptions.
    """
    resolved = resolve_config(session_config)

    def find(session_token: str) -> SessionRecord | None:
        # A plain lookup: rolling a sliding session forward is pointless when
        # it is about to be revoked.
        return session_storage.get(
            token_hash=hash_session_token(session_token, resolved["token_hasher"]),
            now=datetime.now(tz=timezone.utc),
        )

    # Same precedence as resolve_current_session: a stale cookie does not hide
    # a valid bearer token.
    session_token: str | None = None
    session_record: SessionRecord | None = None
    for candidate in (
        request.cookies.get(resolved["cookies"]["name"]),
        get_bearer_token(request),
    ):
        if candidate is None:
            continue
        session_token = session_token or candidate
        if (session_record := find(candidate)) is not None:
            session_token = candidate
            break

    event = hooks.run_before(
        "logout",
        BeforeLogoutEvent(
            request=request,
            response=response,
            session_record=session_record,
            session_token=session_token,
        ),
    )
    revoked_record = event.session_record
    # A hook that picked another token, but left the record alone, revokes the
    # session behind that token.
    if event.session_token != session_token and revoked_record is session_record:
        revoked_record = (
            find(event.session_token) if event.session_token is not None else None
        )

    # Without a session to revoke nothing is written, so the after hook
    # has no commit to wait for.
    on_commit = run_now
    if revoked_record is not None:
        require_immediate_commit(
            session_storage.on_commit,
            COOKIE_SESSION_COMMIT_ERROR.format(action="Logout"),
        )
        session_storage.revoke(
            revoked_record.id,
            revoked_at=datetime.now(tz=timezone.utc),
        )
        on_commit = session_storage.on_commit

    if event.response.cookies is None:
        event.response.cookies = []
    event.response.cookies.append(make_clear_cookie(session_config))
    after_event = AfterLogoutEvent(
        request=event.request,
        response=event.response,
        session_record=revoked_record,
    )
    on_commit(lambda: hooks.run_after("logout", after_event))
    return event.response
