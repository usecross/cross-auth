from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Protocol, TypeVar

from cross_web import HTTPRequest, Response

from ._session import (
    SessionConfig,
    SessionMetadata,
    _build_cookie,
    create_session,
    make_clear_cookie,
    resolve_config,
    resolve_current_session,
)
from ._storage import CommitCallback, SessionRecord, SessionStorage, User
from .hooks import (
    AfterLoginEvent,
    AfterLogoutEvent,
    AfterSessionRevokeEvent,
    BeforeLoginEvent,
    BeforeLogoutEvent,
    BeforeSessionRevokeEvent,
    HookRegistry,
    LogoutScope,
)

if TYPE_CHECKING:
    from ._mfa import MFA

_IssuedT = TypeVar("_IssuedT")

# Raises CrossAuthException unless the user with this id may sign in.
UserCheck = Callable[[str], None]
# Called with the session a login just stored (None for a credential a
# token_issuer minted), before its after hook is scheduled. Raising undoes the
# login: it revokes the session itself first.
AfterIssue = Callable[[SessionRecord | None], None]


def run_login(
    event: BeforeLoginEvent,
    *,
    hooks: HookRegistry,
    issue: Callable[[BeforeLoginEvent], tuple[_IssuedT, SessionRecord | None]],
    on_commit: Callable[[CommitCallback], None],
    check_user: UserCheck | None,
    mfa: MFA | None = None,
    after_issue: AfterIssue | None = None,
) -> tuple[_IssuedT, BeforeLoginEvent]:
    """Run one ``login`` lifecycle around issuing a credential.

    ``check_user`` refuses a user who may not sign in, before the before
    hooks run; pass ``None`` only when the caller has just checked the user
    it logs in. With ``mfa``, a sign-in that needs a second factor and has
    not passed one (``event.mfa_method`` is None) raises ``MFARequired``
    before the hooks run and issues nothing; the caller stores a challenge. ``issue`` creates the credential from the approved event and
    returns it with the Cross Auth session it created, if any. ``on_commit``
    belongs to whatever stores the credential and schedules the after hook
    once it is committed. Hook exceptions propagate: a before-hook failure
    issues nothing; an after-hook failure leaves the issued credential in
    place. ``after_issue`` runs once the credential is stored, before the
    after hook is scheduled; what it raises propagates and no after hook runs.
    """
    if check_user is not None:
        check_user(event.user_id)
    if mfa is not None and event.mfa_method is None:
        mfa.check_sign_in(event.user_id, event.login_method)
    approved = hooks.run_before("login", event)
    _check_login_rewrite(event, approved)

    issued, session_record = issue(approved)
    if after_issue is not None:
        after_issue(session_record)

    after_event = AfterLoginEvent(
        user_id=approved.user_id,
        credential=approved.credential,
        session_record=session_record,
        response=approved.response,
        login_method=approved.login_method,
        mfa_method=approved.mfa_method,
    )
    on_commit(lambda: hooks.run_after("login", after_event))
    return issued, approved


class BrowserLogin(Protocol):
    """Logs a browser in with a session the web framework owns.

    Browser sign-in uses this in place of a Cross Auth cookie session once the
    provider identity is verified and the user's account changes committed.
    """

    def login(
        self,
        user: User,
        *,
        response: Response,
        login_method: str,
        mfa_method: str | None = None,
    ) -> Response:
        """Log ``user`` in through ``run_login`` and return the response.

        ``login_method`` is the provider's id. ``mfa_method`` is the second
        factor the sign-in already passed; without one, ``run_login`` raises
        ``MFARequired`` for a user who needs it. Raise ``CrossAuthException`` to
        refuse a user the framework does not allow to sign in. The callback
        has already checked the context's ``user_can_authenticate``.
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
    if approved.mfa_method != original.mfa_method:
        raise ValueError("login before hooks cannot change mfa_method")
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
    check_user: UserCheck | None,
    metadata: SessionMetadata | None = None,
    login_method: str | None = None,
    mfa: MFA | None = None,
    mfa_method: str | None = None,
    after_issue: AfterIssue | None = None,
) -> Response:
    """Log in with one new session and its cookie appended to ``response``.

    ``check_user`` and ``after_issue`` are as for ``run_login``. Returns the
    hook response; adapters decide how to send it and how to surface hook
    exceptions.
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
            token_prefix=resolved["token_prefix"],
            login_method=event.login_method,
            store_ip=resolved["store_ip"],
            mfa_method=event.mfa_method,
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
            login_method=login_method,
            mfa_method=mfa_method,
        ),
        hooks=hooks,
        issue=issue,
        on_commit=session_storage.on_commit,
        check_user=check_user,
        mfa=mfa,
        after_issue=after_issue,
    )
    return hook_response


def issue_bearer_session(
    user_id: str,
    *,
    hooks: HookRegistry,
    session_storage: SessionStorage,
    session_config: SessionConfig | None,
    check_user: UserCheck | None,
    max_age: int | None = None,
    metadata: SessionMetadata | None = None,
    login_method: str | None = None,
    mfa: MFA | None = None,
    mfa_method: str | None = None,
    after_issue: AfterIssue | None = None,
) -> tuple[str, SessionRecord, int]:
    """Log in with one new session; return its bearer token, record and max_age.

    ``check_user`` and ``after_issue`` are as for ``run_login``.
    """
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
            token_prefix=resolved["token_prefix"],
            login_method=event.login_method,
            store_ip=resolved["store_ip"],
            mfa_method=event.mfa_method,
        )
        return (session_token, session_record), session_record

    (session_token, session_record), approved = run_login(
        BeforeLoginEvent(
            user_id=user_id,
            credential="bearer",
            max_age=max_age if max_age is not None else resolved["max_age"],
            metadata=metadata,
            login_method=login_method,
            mfa_method=mfa_method,
        ),
        hooks=hooks,
        issue=issue,
        on_commit=session_storage.on_commit,
        check_user=check_user,
        mfa=mfa,
        after_issue=after_issue,
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
    scope: LogoutScope = "current",
    mfa: MFA | None = None,
) -> Response:
    """Revoke the request's session and clear the session cookie on ``response``.

    The session token comes from the session cookie, then from an
    ``Authorization: Bearer`` header. ``scope="all"`` revokes every session of that session's user. A
    missing, unknown, expired or already revoked token revokes nothing.
    With ``mfa``, ``scope="all"`` also ends the user's sign-ins that are
    waiting for their second factor, as ``revoke_user_sessions`` does.
    Returns the hook response; adapters decide how to send it and how to
    surface hook exceptions.
    """
    current = resolve_current_session(
        request, session_storage, session_config, refresh=False
    )
    session_record = None if current is None else current.record

    event = hooks.run_before(
        "logout",
        BeforeLogoutEvent(
            request=request,
            response=response,
            session_record=session_record,
            scope=scope,
        ),
    )
    if event.scope not in ("current", "all"):
        raise ValueError("logout before hooks must keep scope 'current' or 'all'")
    revoked_record = event.session_record

    revoked_count = 0
    if revoked_record is not None:
        require_immediate_commit(
            session_storage.on_commit,
            COOKIE_SESSION_COMMIT_ERROR.format(action="Logout"),
        )
        revoked_at = datetime.now(tz=timezone.utc)
        if event.scope == "all":
            if mfa is not None:
                mfa.revoke_challenges(revoked_record.user_id)
            revoked_count = session_storage.revoke_all_for_user(
                revoked_record.user_id, revoked_at=revoked_at
            )
        else:
            revoked = session_storage.revoke(revoked_record.id, revoked_at=revoked_at)
            revoked_count = 1 if revoked else 0

    if event.response.cookies is None:
        event.response.cookies = []
    event.response.cookies.append(make_clear_cookie(session_config))
    # Like session.revoke, the after hook reports revocations only: a logout
    # that revoked nothing still clears the cookie but runs no after hook.
    if revoked_record is None or revoked_count == 0:
        return event.response
    after_event = AfterLogoutEvent(
        request=event.request,
        response=event.response,
        session_record=revoked_record,
        scope=event.scope,
        revoked_count=revoked_count,
    )
    session_storage.on_commit(lambda: hooks.run_after("logout", after_event))
    return event.response


def revoke_user_session(
    session_record: SessionRecord,
    *,
    hooks: HookRegistry,
    session_storage: SessionStorage,
    request: HTTPRequest | None = None,
) -> int:
    """Revoke one session around the ``session.revoke`` hooks.

    The caller has checked who owns the session. Returns 1 if the session was
    still active, else 0: an expired or revoked session is left as it is.
    """
    return _revoke_sessions(
        BeforeSessionRevokeEvent(
            user_id=session_record.user_id,
            scope="one",
            session_record=session_record,
            keep_session_id=None,
            request=request,
        ),
        hooks=hooks,
        session_storage=session_storage,
    )


def revoke_user_sessions(
    user_id: Any,
    *,
    hooks: HookRegistry,
    session_storage: SessionStorage,
    keep_session_id: Any | None = None,
    request: HTTPRequest | None = None,
    mfa: MFA | None = None,
) -> int:
    """Revoke the user's active sessions around the ``session.revoke`` hooks.

    ``keep_session_id`` is left alone (scope ``"others"``); without it every
    session is revoked (scope ``"all"``). Returns how many were revoked.

    With ``mfa``, the user's sign-ins that are waiting for their second
    factor end too, once the before hooks allow it, also when no session was
    active: revoking sessions is how a user locks out someone who knows their
    password, and that person's sign-in may be waiting for its code.
    """
    return _revoke_sessions(
        BeforeSessionRevokeEvent(
            user_id=user_id,
            scope="all" if keep_session_id is None else "others",
            session_record=None,
            keep_session_id=keep_session_id,
            request=request,
        ),
        hooks=hooks,
        session_storage=session_storage,
        mfa=mfa,
    )


def _revoke_sessions(
    event: BeforeSessionRevokeEvent,
    *,
    hooks: HookRegistry,
    session_storage: SessionStorage,
    mfa: MFA | None = None,
) -> int:
    # Fix the target first: a hook may refuse the revocation, but changing
    # the live record must not make it revoke another session.
    session_id = None if event.session_record is None else event.session_record.id
    hooks.run_before("session.revoke", event)
    if mfa is not None:
        mfa.revoke_challenges(event.user_id)

    revoked_at = datetime.now(tz=timezone.utc)
    if session_id is not None:
        revoked = session_storage.revoke(session_id, revoked_at=revoked_at)
        revoked_count = 1 if revoked else 0
    else:
        revoked_count = session_storage.revoke_all_for_user(
            event.user_id,
            revoked_at=revoked_at,
            except_session_id=event.keep_session_id,
        )

    if revoked_count == 0:
        return 0
    after_event = AfterSessionRevokeEvent(
        user_id=event.user_id,
        scope=event.scope,
        session_record=event.session_record,
        keep_session_id=event.keep_session_id,
        request=event.request,
        revoked_count=revoked_count,
    )
    session_storage.on_commit(lambda: hooks.run_after("session.revoke", after_event))
    return revoked_count
