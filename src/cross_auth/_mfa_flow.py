"""Two-factor flows shared by every framework.

The functions here work on a ``cross_web.HTTPRequest`` and a ``Context``, like
``handle_callback``. A framework supplies an ``MFASessions``: how to find the
signed-in user and their session, and how to revoke their other sessions. The
FastAPI router uses ``CrossAuthSessions`` (Cross Auth's own sessions); the
Django views pass one built on Django sessions.
"""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
from collections.abc import Collection
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol, cast
from urllib.parse import parse_qsl

from cross_web import Cookie, HTTPRequest

from ._authorization_code import (
    AUTH_CODE_KEY,
    AUTH_CODE_TTL,
    AuthorizationCodeGrantData,
)
from ._context import Context
from ._issuer import _bearer_token
from ._login import (
    AfterIssue,
    BrowserLogin,
    issue_bearer_session,
    login_with_session,
    revoke_user_sessions,
)
from ._mfa import (
    DEVICE_LOGIN_METHOD,
    MFA,
    Challenge,
    ChallengeKind,
    MFARequired,
    MFAStatus,
    TotpConfirmation,
    TotpEnrollment,
)
from ._session import SessionMetadata, request_metadata
from ._storage import SessionRecord, User
from ._tokens import TokenIssueRequest
from .exceptions import CrossAuthException
from .hooks import AfterTokenPasswordEvent
from .utils._response import Response

logger = logging.getLogger(__name__)

_REAUTH_KEY = "mfa:reauth:{digest}"

# What POST /mfa/verify finishes: the sign-ins a browser waits on. A bearer
# challenge finishes through verify_mfa, and a password grant's through
# /token, where that grant's own checks run.
VERIFY_ROUTE_KINDS: tuple[ChallengeKind, ...] = (
    "cookie",
    "browser",
    "authorization_code",
)


@dataclass(frozen=True)
class MFASession:
    """The signed-in user a 2FA request acts for."""

    user: User
    # Names the session; enrollments are bound to it.
    session_id: str
    # When the session's sign-in completed.
    signed_in_at: datetime
    # Cross Auth's session record, when the session is one.
    record: SessionRecord | None = None
    # How the session signed in: a device login's creation is no proof of
    # identity (see authenticated_at).
    login_method: str | None = None


class MFASessions(Protocol):
    def current(self, request: HTTPRequest, context: Context) -> MFASession | None:
        """The request's signed-in user and session, or ``None``."""
        ...

    def revoke_others(
        self, request: HTTPRequest, context: Context, current: MFASession
    ) -> None:
        """End the user's other sessions once 2FA is turned on."""
        ...


class CrossAuthSessions:
    """``MFASessions`` for Cross Auth's own cookie and bearer sessions."""

    def current(self, request: HTTPRequest, context: Context) -> MFASession | None:
        resolved = context.resolve_current_session(request, load_user=True)
        if resolved is None or resolved.user is None:
            return None
        return MFASession(
            user=resolved.user,
            session_id=str(resolved.record.id),
            signed_in_at=resolved.record.created_at,
            record=resolved.record,
            login_method=resolved.record.login_method,
        )

    def revoke_others(
        self, request: HTTPRequest, context: Context, current: MFASession
    ) -> None:
        assert context.session_storage is not None and current.record is not None
        revoke_user_sessions(
            current.record.user_id,
            keep_session_id=current.record.id,
            hooks=context.hooks,
            session_storage=context.session_storage,
            request=request,
            mfa=context.mfa,
        )


def require_mfa(context: Context) -> MFA:
    if context.mfa is None:
        raise RuntimeError(
            "Two-factor authentication is not configured: pass config['mfa'] "
            "and an mfa_storage"
        )
    return context.mfa


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def authenticated_at(context: Context, current: MFASession) -> datetime | None:
    """When the user last proved who they are in this session, or ``None``.

    A sign-in counts, and so does ``reauthenticate``. A device login's sign-in
    does not: the user approved the device from another session and proved
    nothing in this one, so a stolen browser session could otherwise approve
    a device and change 2FA settings from it at once. Such a session counts
    only from a ``reauthenticate`` in it.
    """
    times: list[datetime] = []
    if current.login_method != DEVICE_LOGIN_METHOD:
        times.append(_aware(current.signed_in_at))
    raw = context.secondary_storage.get(
        _REAUTH_KEY.format(digest=_digest(current.session_id))
    )
    if raw is not None:
        try:
            times.append(_aware(datetime.fromisoformat(raw)))
        except ValueError:
            pass
    return max(times, default=None)


def _unauthorized() -> CrossAuthException:
    return CrossAuthException("unauthorized", "Not logged in", status_code=401)


def require_session(
    request: HTTPRequest, context: Context, sessions: MFASessions
) -> MFASession:
    current = sessions.current(request, context)
    if current is None:
        raise _unauthorized()
    return current


# The operations behind the routes, for applications that build their own
# pages. Each takes the resolved session.


def get_status(context: Context, current: MFASession) -> MFAStatus:
    return require_mfa(context).status(current.user.id)


def reauthenticate(
    context: Context,
    current: MFASession,
    *,
    password: str | None = None,
    code: str | None = None,
    recovery_code: str | None = None,
) -> datetime:
    mfa = require_mfa(context)
    until = mfa.reauthenticate(
        current.user, password=password, code=code, recovery_code=recovery_code
    )
    now = datetime.now(tz=timezone.utc)
    context.secondary_storage.set(
        _REAUTH_KEY.format(digest=_digest(current.session_id)),
        now.isoformat(),
        ttl=max(int((until - now).total_seconds()), 1),
    )
    return until


def start_totp_enrollment(
    context: Context, current: MFASession, *, name: str | None = None
) -> TotpEnrollment:
    return require_mfa(context).start_totp_enrollment(
        current.user,
        session_id=current.session_id,
        authenticated_at=authenticated_at(context, current),
        name=name,
    )


def confirm_totp_enrollment(
    request: HTTPRequest,
    context: Context,
    sessions: MFASessions,
    current: MFASession,
    *,
    enrollment_id: str,
    code: str,
    revoke_other_sessions: bool = True,
) -> TotpConfirmation:
    confirmation = require_mfa(context).confirm_totp_enrollment(
        current.user,
        session_id=current.session_id,
        enrollment_id=enrollment_id,
        code=code,
    )
    if revoke_other_sessions and confirmation.enabled_mfa:
        # The factor and its recovery codes are stored by now: a refused or
        # failed revocation must not keep the codes from the user.
        try:
            sessions.revoke_others(request, context, current)
        except Exception:
            logger.exception("Could not sign out other sessions after enabling 2FA")
    return confirmation


def regenerate_recovery_codes(context: Context, current: MFASession) -> list[str]:
    return require_mfa(context).regenerate_recovery_codes(
        current.user, authenticated_at=authenticated_at(context, current)
    )


def remove_mfa_factor(
    context: Context, current: MFASession, factor_id: str
) -> MFAStatus:
    return require_mfa(context).remove_factor(
        current.user, factor_id, authenticated_at=authenticated_at(context, current)
    )


# Challenges ----------------------------------------------------------------


def challenge_cookie(
    request: HTTPRequest, context: Context, value: str, *, max_age: int
) -> Cookie:
    secure = (context.base_url or str(request.url)).startswith("https://")
    return Cookie(
        name=require_mfa(context).challenge_cookie,
        value=value,
        secure=secure,
        path="/",
        max_age=max_age,
        httponly=True,
        samesite="lax",
    )


def browser_challenge(
    request: HTTPRequest,
    context: Context,
    required: MFARequired,
    *,
    kind: ChallengeKind,
    data: dict[str, Any],
) -> Response:
    """Store a challenge and send the browser to the verify page with it.

    The token travels only in an HttpOnly cookie, never in the URL.
    """
    mfa = require_mfa(context)
    if mfa.verify_url is None:
        return Response.error(
            "server_error",
            "config['mfa']['verify_url'] is required for browser sign-ins with "
            "two-factor authentication",
            status_code=500,
        )
    started = mfa.start_challenge(required, kind=kind, data=data)
    assert started.challenge is not None
    return Response.redirect(
        mfa.verify_url,
        cookies=[
            challenge_cookie(
                request, context, started.challenge, max_age=mfa.challenge_ttl
            )
        ],
    )


def _metadata(data: dict[str, Any]) -> SessionMetadata | None:
    metadata = data.get("metadata")
    return None if metadata is None else cast(SessionMetadata, metadata)


@dataclass(frozen=True)
class Finished:
    """What finishing a challenge produced."""

    response: Response
    # Set for bearer sign-ins.
    token: str | None = None
    record: SessionRecord | None = None
    user: User | None = None
    # The challenge that was finished, and the method that passed it.
    challenge: Challenge | None = None
    mfa_method: str | None = None


def _wants_json(request: HTTPRequest) -> bool:
    content_type = request.content_type or ""
    accept = request.headers.get("accept") or request.headers.get("Accept") or ""
    return "json" in content_type or "application/json" in accept


def _navigate(request: HTTPRequest, url: str, cookies: list[Cookie]) -> Response:
    if _wants_json(request):
        return Response(
            status_code=200,
            body=json.dumps({"redirect_to": url}),
            headers={"Content-Type": "application/json"},
            cookies=cookies,
        )
    response = Response.redirect(url, cookies=cookies)
    response.status_code = 303
    return response


def finish_challenge(
    request: HTTPRequest,
    context: Context,
    token: str,
    *,
    kinds: Collection[ChallengeKind],
    code: str | None = None,
    recovery_code: str | None = None,
    login: BrowserLogin | None = None,
) -> Finished:
    """Check the code and complete the sign-in the challenge was waiting for.

    ``kinds`` are the challenges this caller finishes; any other answers
    ``invalid_challenge`` before its code is checked (see
    ``MFA.verify_challenge``).
    """
    mfa = require_mfa(context)
    challenge, method = mfa.verify_challenge(
        token, kinds=kinds, code=code, recovery_code=recovery_code
    )
    finished = _complete(request, context, challenge, method, login=login)
    return replace(finished, challenge=challenge, mfa_method=method)


def _unless_revoked(context: Context, mfa: MFA, challenge: Challenge) -> AfterIssue:
    """End a sign-in whose user's sessions were revoked while its code was checked.

    Asked once the credential is stored, not before: every revocation writes
    the user's marker before it revokes their sessions, so either it finds
    this session and revokes it, or this finds its marker. Asked before the
    write, a revocation in between would do neither.
    """

    def check(record: SessionRecord | None) -> None:
        if not mfa.revoked(challenge):
            return
        if record is not None and context.session_storage is not None:
            # Only this session: the revocation may have kept another.
            context.session_storage.revoke(
                record.id, revoked_at=datetime.now(tz=timezone.utc)
            )
        raise _invalid_challenge()

    return check


def _complete(
    request: HTTPRequest,
    context: Context,
    challenge: Challenge,
    method: str,
    *,
    login: BrowserLogin | None,
) -> Finished:
    mfa = require_mfa(context)
    data = challenge.data
    clear = [challenge_cookie(request, context, "", max_age=0)]
    unless_revoked = _unless_revoked(context, mfa, challenge)

    if challenge.kind == "bearer":
        assert context.session_storage is not None
        session_token, record, max_age = issue_bearer_session(
            challenge.user_id,
            hooks=context.hooks,
            session_storage=context.session_storage,
            session_config=context.session_config,
            check_user=context.check_user_id_can_authenticate,
            max_age=data.get("max_age"),
            metadata=_metadata(data),
            login_method=challenge.login_method,
            mfa=mfa,
            mfa_method=method,
            after_issue=unless_revoked,
        )
        body = {
            "access_token": session_token,
            "token_type": "Bearer",
            "expires_in": max_age,
        }
        return Finished(
            Response(
                status_code=200,
                body=json.dumps(body),
                headers={
                    "Content-Type": "application/json",
                    "Cache-Control": "no-store",
                },
            ),
            token=session_token,
            record=record,
        )

    if challenge.kind == "token":
        user = context.accounts_storage.find_user_by_id(challenge.user_id)
        if user is None:
            raise _invalid_challenge()
        issued = context.issue_token_result(
            TokenIssueRequest(
                user_id=challenge.user_id,
                client_id=data["client_id"],
                grant_type="password",
                scope=data.get("scope"),
                http_request=request,
                username=data.get("username"),
                login_method=challenge.login_method,
                mfa_method=method,
            ),
            after_issue=unless_revoked,
        )
        token_data = _bearer_token(issued)
        # The token.password after hook a sign-in without 2FA would have run.
        after_event = AfterTokenPasswordEvent(
            client_id=data["client_id"],
            username=data.get("username") or "",
            user=user,
            scope=data.get("scope"),
            token_response=token_data,
        )
        issued.on_commit(lambda: context.hooks.run_after("token.password", after_event))
        body = {
            "access_token": issued.token,
            "token_type": "Bearer",
            "expires_in": issued.expires_in,
            "scope": "",
        }
        return Finished(
            Response(
                status_code=200,
                body=json.dumps(body),
                headers={
                    "Content-Type": "application/json",
                    "Cache-Control": "no-store",
                },
            ),
            token=issued.token,
        )

    if challenge.kind == "authorization_code":
        context.check_user_id_can_authenticate(challenge.user_id)
        # The client's registration may have changed while the user found
        # their code: as the callback does, send no code to a URI the client
        # no longer registers.
        if context.oauth_server is None:
            raise CrossAuthException("invalid_request", "The OAuth server is disabled")
        if not context.is_valid_redirect_uri(
            data["redirect_uri"], client_id=data["client_id"]
        ):
            raise CrossAuthException(
                "invalid_redirect_uri",
                "Callback is no longer registered for this client",
            )
        auth_code = secrets.token_urlsafe(32)
        grant = AuthorizationCodeGrantData(
            user_id=challenge.user_id,
            expires_at=datetime.now(tz=timezone.utc) + AUTH_CODE_TTL,
            client_id=data["client_id"],
            redirect_uri=data["redirect_uri"],
            code_challenge=data["code_challenge"],
            code_challenge_method=data["code_challenge_method"],
            login_method=challenge.login_method,
            mfa_method=method,
        )
        code_key = AUTH_CODE_KEY.format(code=auth_code)
        context.secondary_storage.set(
            code_key,
            grant.model_dump_json(),
            ttl=int(AUTH_CODE_TTL.total_seconds()),
        )
        # As for a session: asked once the code is stored.
        if mfa.revoked(challenge):
            context.secondary_storage.delete(code_key)
            raise _invalid_challenge()
        params = {"code": auth_code}
        if data.get("state"):
            params["state"] = data["state"]
        redirect = Response.redirect(data["redirect_uri"], query_params=params)
        location = (redirect.headers or {})["Location"]
        return Finished(_navigate(request, location, clear))

    if challenge.kind == "framework":
        # A framework that logs users in itself, such as Django's password
        # login, finishes the sign-in from the data it stored.
        user = context.accounts_storage.find_user_by_id(challenge.user_id)
        if user is None:
            raise _invalid_challenge()
        # Asked again, as every other kind does: the user may have been
        # refused since the challenge started.
        context.check_user_can_authenticate(user)
        return Finished(Response(status_code=204, cookies=clear), user=user)

    # "browser" (an OAuth callback) and "cookie" (the application's login()).
    next_url = data.get("next_url") or context.default_next_url
    if login is not None:
        user = context.accounts_storage.find_user_by_id(challenge.user_id)
        if user is None:
            raise _invalid_challenge()
        context.check_user_can_authenticate(user)
        logged_in = cast(
            Response,
            login.login(
                user,
                response=Response.redirect(next_url),
                login_method=challenge.login_method or "",
                mfa_method=method,
            ),
        )
        logged_in.cookies = [*(logged_in.cookies or []), *clear]
        return Finished(logged_in, user=user)

    assert context.session_storage is not None
    # The navigation is the login's response, so a login hook's changes to it
    # reach the browser, as with a sign-in without 2FA.
    response = cast(
        Response,
        login_with_session(
            challenge.user_id,
            response=_navigate(request, next_url, []),
            hooks=context.hooks,
            session_storage=context.session_storage,
            session_config=context.session_config,
            check_user=context.check_user_id_can_authenticate,
            metadata=_metadata(data)
            or request_metadata(request, context.session_config),
            login_method=challenge.login_method,
            mfa=mfa,
            mfa_method=method,
            after_issue=unless_revoked,
        ),
    )
    response.cookies = [*(response.cookies or []), *clear]
    return Finished(response)


def _invalid_challenge() -> CrossAuthException:
    return CrossAuthException(
        "invalid_challenge", "This sign-in has expired; sign in again"
    )


# Route handlers --------------------------------------------------------------


def read_fields(request: HTTPRequest) -> dict[str, Any]:
    """A JSON object or form body as a dict; empty when there is none."""
    content_type = request.content_type or ""
    if "json" in content_type:
        body = request.body
        if not body:
            return {}
        try:
            value = json.loads(body)
        except (ValueError, UnicodeDecodeError) as error:
            raise CrossAuthException("invalid_request", "Invalid JSON body") from error
        if not isinstance(value, dict):
            raise CrossAuthException("invalid_request", "The body must be an object")
        return value
    form = dict(request.post_data)
    if not form and "x-www-form-urlencoded" in content_type:
        body = request.body
        text = body.decode("utf-8") if isinstance(body, bytes) else body
        form = dict(parse_qsl(text))
    return {
        key: value.decode("utf-8") if isinstance(value, bytes) else value
        for key, value in form.items()
    }


def _optional_str(fields: dict[str, Any], name: str) -> str | None:
    value = fields.get(name)
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise CrossAuthException("invalid_request", f"{name} must be a string")
    return value


def _required_str(fields: dict[str, Any], name: str) -> str:
    value = _optional_str(fields, name)
    if value is None:
        raise CrossAuthException("invalid_request", f"{name} is required")
    return value


def json_response(body: Any, *, status_code: int = 200) -> Response:
    return Response(
        status_code=status_code,
        body=json.dumps(body),
        headers={"Content-Type": "application/json", "Cache-Control": "no-store"},
    )


def error_response(error: CrossAuthException) -> Response:
    body: dict[str, Any] = {"error": error.error}
    if error.error_description:
        body["error_description"] = error.error_description
    methods = getattr(error, "methods", None)
    if methods is not None:
        body["methods"] = methods
    return Response(
        status_code=error.status_code,
        body=json.dumps(body),
        headers={"Content-Type": "application/json"},
    )


def status_handler(
    request: HTTPRequest, context: Context, sessions: MFASessions
) -> Response:
    """GET /mfa — the signed-in user's factors and recovery codes left."""
    try:
        current = require_session(request, context, sessions)
        return json_response(get_status(context, current).to_json())
    except CrossAuthException as error:
        return error_response(error)


def reauthenticate_handler(
    request: HTTPRequest, context: Context, sessions: MFASessions
) -> Response:
    """POST /reauthenticate — allow 2FA changes for a few minutes."""
    try:
        current = require_session(request, context, sessions)
        fields = read_fields(request)
        until = reauthenticate(
            context,
            current,
            password=_optional_str(fields, "password"),
            code=_optional_str(fields, "code"),
            recovery_code=_optional_str(fields, "recovery_code"),
        )
        now = datetime.now(tz=timezone.utc)
        return json_response(
            {"authenticated_at": now.isoformat(), "expires_at": until.isoformat()}
        )
    except CrossAuthException as error:
        return error_response(error)


def enroll_handler(
    request: HTTPRequest, context: Context, sessions: MFASessions
) -> Response:
    """POST /mfa/totp/enroll — a new secret, waiting for its first code."""
    try:
        current = require_session(request, context, sessions)
        fields = read_fields(request)
        enrollment = start_totp_enrollment(
            context, current, name=_optional_str(fields, "name")
        )
        return json_response(enrollment.to_json())
    except CrossAuthException as error:
        return error_response(error)


def confirm_handler(
    request: HTTPRequest, context: Context, sessions: MFASessions
) -> Response:
    """POST /mfa/totp/confirm — store the factor once its first code checks out."""
    try:
        current = require_session(request, context, sessions)
        fields = read_fields(request)
        confirmation = confirm_totp_enrollment(
            request,
            context,
            sessions,
            current,
            enrollment_id=_required_str(fields, "enrollment_id"),
            code=_required_str(fields, "code"),
        )
        return json_response(confirmation.to_json(), status_code=201)
    except CrossAuthException as error:
        return error_response(error)


def recovery_codes_handler(
    request: HTTPRequest, context: Context, sessions: MFASessions
) -> Response:
    """POST /mfa/recovery-codes — replace the recovery codes."""
    try:
        current = require_session(request, context, sessions)
        return json_response(
            {"recovery_codes": regenerate_recovery_codes(context, current)}
        )
    except CrossAuthException as error:
        return error_response(error)


def remove_handler(
    request: HTTPRequest, context: Context, sessions: MFASessions
) -> Response:
    """POST /mfa/factors/{factor_id}/remove — remove one factor."""
    try:
        current = require_session(request, context, sessions)
        status = remove_mfa_factor(
            context, current, str(request.path_params["factor_id"])
        )
        return json_response(status.to_json())
    except CrossAuthException as error:
        return error_response(error)


def verify_handler(
    request: HTTPRequest,
    context: Context,
    *,
    login: BrowserLogin | None = None,
) -> Response:
    """POST /mfa/verify — finish a sign-in that is waiting for its second factor.

    The challenge comes from the body's ``challenge`` or the challenge
    cookie. Form posts that fail go back to ``verify_url`` with ``?error=``.
    """
    mfa = require_mfa(context)
    fields: dict[str, Any] = {}
    try:
        fields = read_fields(request)
        token = _optional_str(fields, "challenge") or request.cookies.get(
            mfa.challenge_cookie
        )
        if not token:
            raise _invalid_challenge()
        return finish_challenge(
            request,
            context,
            token,
            kinds=VERIFY_ROUTE_KINDS,
            code=_optional_str(fields, "code"),
            recovery_code=_optional_str(fields, "recovery_code"),
            login=login,
        ).response
    except MFARequired as error:
        # Only when a hook changed what the sign-in needs; never expected.
        return error_response(error)
    except CrossAuthException as error:
        if not _wants_json(request) and mfa.verify_url is not None:
            redirect = Response.redirect(
                mfa.verify_url, query_params={"error": error.error}
            )
            redirect.status_code = 303
            return redirect
        return error_response(error)


def expires_in(seconds: int) -> datetime:
    return datetime.now(tz=timezone.utc) + timedelta(seconds=seconds)
