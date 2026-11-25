"""The OAuth 2.0 Device Authorization Grant (RFC 8628).

A CLI or another input-constrained client asks ``POST /device/code`` for two
codes: a long ``device_code`` it keeps, and a short ``user_code`` it shows the
user with the application's ``verification_uri``. The user signs in there,
enters the code and approves the request, while the device polls ``/token``
with its device code until it gets a token.

Approval only records the decision. The session is created by the poll that
consumes it, through the ``login`` hooks like any other token, so a request
the device stops polling for leaves no session behind.

State lives in ``SecondaryStorage`` alone, under SHA-256 hashes of the codes,
and every key expires with the request:

- ``oauth:device:request:{hash}`` holds the request. It exists until the
  request expires or a poll consumes its decision: a poll that finds it and
  no decision answers ``authorization_pending``, and one that finds nothing
  answers ``expired_token``.
- ``oauth:device:user_code:{hash}`` points the user code at the request while
  it waits for a decision. Approving or denying pops it, so of two decisions
  only one wins.
- ``oauth:device:decision:{hash}`` holds the decision until a poll pops it,
  so of two polls only one gets a token.
- ``oauth:device:poll:{hash}`` remembers the last poll and the interval the
  device must keep, for ``slow_down``.
"""

from __future__ import annotations

import hashlib
import math
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from cross_web import HTTPRequest
from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    ValidationError,
)

from ._clients import OAuthClient
from ._context import Context
from ._oauth_server import DeviceGrant
from ._route import Route
from ._session import (
    ResolvedSession,
    clean_ip,
    clean_user_agent,
    request_metadata,
)
from ._session_routes import _hook_error, _json, _session_endpoint
from ._storage import SecondaryStorage
from .exceptions import CrossAuthException
from .hooks import (
    AfterDeviceApproveEvent,
    AfterDeviceCodeEvent,
    BeforeDeviceApproveEvent,
    BeforeDeviceCodeEvent,
)
from .utils._response import Response

DEVICE_CODE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"

REQUEST_KEY = "oauth:device:request:{hash}"
USER_CODE_KEY = "oauth:device:user_code:{hash}"
DECISION_KEY = "oauth:device:decision:{hash}"
POLL_KEY = "oauth:device:poll:{hash}"

# RFC 8628 section 6.1's example: consonants only, so no code spells a word or
# holds an O or an I to mistake for a digit. Eight of them carry 34.5 bits.
USER_CODE_ALPHABET = "BCDFGHJKLMNPQRSTVWXZ"
USER_CODE_LENGTH = 8
# Anything else a user types around the code: separators, spaces, a pasted
# newline. Digits stay, so a mistyped code doesn't match by accident.
_NOT_CODE_CHARACTER = re.compile(r"[^A-Za-z0-9]")
_MAX_USER_CODE_INPUT = 64
# A new code that collides with a pending one is drawn again; with 20**8
# codes, needing more than a few draws means the storage is broken.
_USER_CODE_DRAWS = 8
# RFC 8628 section 3.5: slow_down adds five seconds to the interval, for that
# poll and every later one.
_SLOW_DOWN_STEP = 5


class DeviceAuthorization(BaseModel):
    """A pending device authorization request, for the approval page.

    ``client_name`` comes from the client's current registration. ``ip`` and
    ``user_agent`` are those of the device that asked, cleaned as session
    metadata is; ``ip`` is ``None`` when ``config["session"]["store_ip"]`` is
    off. ``metadata`` is what a ``device.code`` before hook attached.
    """

    model_config = ConfigDict(frozen=True)

    client_id: str
    client_name: str | None
    scope: str | None
    ip: str | None = Field(description="The address the device asked from")
    user_agent: str | None = Field(description="The user agent of the device")
    metadata: dict[str, JsonValue] = Field(
        description="What the application attached to the request"
    )
    created_at: AwareDatetime
    expires_at: AwareDatetime


class DeviceAuthorizationResponse(BaseModel):
    """The answer to ``POST /device/code`` (RFC 8628 section 3.2)."""

    device_code: str = Field(
        description="The code the device polls /token with", repr=False
    )
    user_code: str = Field(description="The code the user enters", repr=False)
    verification_uri: str = Field(description="Where the user enters the code")
    verification_uri_complete: str = Field(
        description="verification_uri with the user code in its query", repr=False
    )
    expires_in: int = Field(description="Seconds until both codes expire")
    interval: int = Field(description="Seconds to wait between polls of /token")


class DeviceDecisionRequest(BaseModel):
    user_code: str = Field(description="The code the device showed", repr=False)


class _DeviceRequestData(BaseModel):
    client_id: str
    scope: str | None
    ip: str | None
    user_agent: str | None
    metadata: dict[str, JsonValue]
    created_at: AwareDatetime
    expires_at: AwareDatetime
    interval: int


class _Decision(BaseModel):
    approved: bool
    user_id: str


class _PollState(BaseModel):
    last_polled_at: AwareDatetime
    interval: int


@dataclass(frozen=True)
class _PendingRequest:
    device_hash: str
    user_code_key: str
    data: _DeviceRequestData
    authorization: DeviceAuthorization


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def normalize_user_code(user_code: str) -> str | None:
    """Return ``user_code`` as Cross Auth stores it, or ``None`` if it can't be one.

    Users type the code, so case and everything but letters and digits are
    ignored: ``bcdf ghjk`` and ``BCDF-GHJK`` are the same code.
    """
    if len(user_code) > _MAX_USER_CODE_INPUT:
        return None
    normalized = _NOT_CODE_CHARACTER.sub("", user_code).upper()
    if len(normalized) != USER_CODE_LENGTH or any(
        character not in USER_CODE_ALPHABET for character in normalized
    ):
        return None
    return normalized


def format_user_code(user_code: str) -> str:
    """Return a normalized user code as users see it, ``XXXX-XXXX``."""
    half = USER_CODE_LENGTH // 2
    return f"{user_code[:half]}-{user_code[half:]}"


def _device_grant(context: Context) -> DeviceGrant:
    device = None if context.oauth_server is None else context.oauth_server.device
    if device is None:
        raise RuntimeError(
            "The device grant is not enabled: pass "
            "OAuthServer(device=DeviceGrant(verification_uri=...))"
        )
    return device


def _seconds_left(expires_at: datetime, now: datetime | None = None) -> int | None:
    """Seconds until ``expires_at``, rounded up, or ``None`` once it passed.

    Every key a request writes expires with the request rather than a full
    ``expires_in`` after the write.
    """
    if now is None:
        now = datetime.now(tz=timezone.utc)
    left = (expires_at - now).total_seconds()
    return math.ceil(left) if left > 0 else None


def _verification_uri_complete(verification_uri: str, user_code: str) -> str:
    parts = urlsplit(verification_uri)
    query = [
        *parse_qsl(parts.query, keep_blank_values=True),
        ("user_code", user_code),
    ]
    return urlunsplit(parts._replace(query=urlencode(query)))


def _unused_user_code(storage: SecondaryStorage) -> str:
    """Draw a user code no pending request has.

    A collision would point the earlier user's code at another device, so a
    user could approve a device they never saw. ``get`` then ``set`` is not
    atomic, but two requests drawing the same code at the same moment is far
    less likely than a collision with one of many pending codes.
    """
    for _ in range(_USER_CODE_DRAWS):
        user_code = "".join(
            secrets.choice(USER_CODE_ALPHABET) for _ in range(USER_CODE_LENGTH)
        )
        if storage.get(USER_CODE_KEY.format(hash=_hash(user_code))) is None:
            return user_code
    raise RuntimeError("Could not draw an unused device user code")


def _authorization(
    data: _DeviceRequestData, client: OAuthClient
) -> DeviceAuthorization:
    return DeviceAuthorization(
        client_id=data.client_id,
        client_name=client.client_name,
        scope=data.scope,
        ip=data.ip,
        user_agent=data.user_agent,
        metadata=data.metadata,
        created_at=data.created_at,
        expires_at=data.expires_at,
    )


def _form_value(request: HTTPRequest, name: str) -> str | None:
    value = request.post_data.get(name)
    return value if isinstance(value, str) and value else None


def _code_error(error: str, description: str | None) -> Response:
    # The device authorization endpoint answers errors as the token endpoint
    # does (RFC 8628 section 3.2), hook errors included.
    return Response.error(error, error_description=description)


def _check_code_rewrite(
    original: BeforeDeviceCodeEvent, approved: BeforeDeviceCodeEvent
) -> None:
    if (
        approved.client_id != original.client_id
        or approved.scope != original.scope
        or approved.request is not original.request
    ):
        raise ValueError("device.code before hooks can only change metadata")


def request_device_authorization(request: HTTPRequest, context: Context) -> Response:
    """POST /device/code — start a device authorization request.

    The form has the registered ``client_id`` and, optionally, a ``scope``.
    Answers with both codes, where to enter the user code, and how long and
    how often to poll (RFC 8628 sections 3.1 and 3.2).
    """
    device = _device_grant(context)
    client_id = _form_value(request, "client_id")
    if client_id is None:
        return _code_error("invalid_request", "client_id is required")
    client = context.get_client(client_id)
    if client is None:
        return _code_error("invalid_client", "Unknown client")
    scope = _form_value(request, "scope")

    event = BeforeDeviceCodeEvent(client_id=client_id, scope=scope, request=request)
    try:
        approved = context.hooks.run_before("device.code", event)
    except CrossAuthException as e:
        return _code_error(e.error, e.error_description)
    _check_code_rewrite(event, approved)

    now = datetime.now(tz=timezone.utc)
    # The device's own address and user agent, which the approval page shows
    # so the user can tell whether the request is theirs.
    device_metadata = request_metadata(request, context.session_config)
    try:
        data = _DeviceRequestData(
            client_id=client_id,
            scope=scope,
            ip=clean_ip(device_metadata.get("ip")),
            user_agent=clean_user_agent(device_metadata.get("user_agent")),
            metadata=approved.metadata,
            created_at=now,
            expires_at=now + timedelta(seconds=device.expires_in),
            interval=device.interval,
        )
    except ValidationError as e:
        raise TypeError("device.code before hooks must set JSON metadata") from e

    storage = context.secondary_storage
    device_code = secrets.token_urlsafe(32)
    device_hash = _hash(device_code)
    user_code = _unused_user_code(storage)
    # The request first: a user code that resolves always finds its request.
    storage.set(
        REQUEST_KEY.format(hash=device_hash),
        data.model_dump_json(),
        ttl=device.expires_in,
    )
    storage.set(
        USER_CODE_KEY.format(hash=_hash(user_code)),
        device_hash,
        ttl=device.expires_in,
    )

    context.hooks.run_after(
        "device.code",
        AfterDeviceCodeEvent(
            request=request, device_authorization=_authorization(data, client)
        ),
    )

    shown_code = format_user_code(user_code)
    body = DeviceAuthorizationResponse(
        device_code=device_code,
        user_code=shown_code,
        verification_uri=device.verification_uri,
        verification_uri_complete=_verification_uri_complete(
            device.verification_uri, shown_code
        ),
        expires_in=device.expires_in,
        interval=device.interval,
    )
    return Response(
        status_code=200,
        body=body.model_dump_json(),
        headers={
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
        },
    )


def _find_pending(context: Context, user_code: str) -> _PendingRequest | None:
    """Return the request ``user_code`` belongs to while it awaits a decision.

    Unknown, expired and decided codes, and requests whose client is no
    longer registered, return ``None``.
    """
    _device_grant(context)
    normalized = normalize_user_code(user_code)
    if normalized is None:
        return None
    storage = context.secondary_storage
    user_code_key = USER_CODE_KEY.format(hash=_hash(normalized))
    device_hash = storage.get(user_code_key)
    if device_hash is None:
        return None
    raw = storage.get(REQUEST_KEY.format(hash=device_hash))
    if raw is None:
        return None
    try:
        data = _DeviceRequestData.model_validate_json(raw)
    except ValidationError:
        return None
    if _seconds_left(data.expires_at) is None:
        return None
    client = context.get_client(data.client_id)
    if client is None:
        return None
    return _PendingRequest(
        device_hash=device_hash,
        user_code_key=user_code_key,
        data=data,
        authorization=_authorization(data, client),
    )


def _decide(context: Context, pending: _PendingRequest, decision: _Decision) -> bool:
    """Record ``decision`` unless another approval or denial got there first."""
    storage = context.secondary_storage
    # The single-use step: of concurrent decisions, only the one that pops
    # the user code records anything.
    if storage.pop(pending.user_code_key) != pending.device_hash:
        return False
    ttl = _seconds_left(pending.data.expires_at)
    if ttl is None:
        return False
    storage.set(
        DECISION_KEY.format(hash=pending.device_hash),
        decision.model_dump_json(),
        ttl=ttl,
    )
    return True


def get_device_authorization(
    context: Context, user_code: str
) -> DeviceAuthorization | None:
    """Return the pending request ``user_code`` belongs to, or ``None``."""
    pending = _find_pending(context, user_code)
    return None if pending is None else pending.authorization


def approve_device_authorization(
    context: Context,
    user_code: str,
    *,
    user_id: str,
    request: HTTPRequest | None = None,
) -> bool:
    """Approve the request ``user_code`` belongs to for ``user_id``.

    Returns False, and changes nothing, when no pending request has that
    code: unknown, expired, or already approved or denied. A user
    ``user_can_authenticate`` refuses, or a ``device.approve`` before hook
    that raises, raises ``CrossAuthException`` and leaves the request
    pending. The device's next poll creates the session.
    """
    pending = _find_pending(context, user_code)
    if pending is None:
        return False
    # Checked here so a refused user can't approve, and again when the poll
    # creates the session, since the user may be refused in between.
    context.check_user_id_can_authenticate(user_id)
    context.hooks.run_before(
        "device.approve",
        BeforeDeviceApproveEvent(
            user_id=user_id,
            device_authorization=pending.authorization,
            request=request,
        ),
    )
    if not _decide(context, pending, _Decision(approved=True, user_id=user_id)):
        return False
    context.hooks.run_after(
        "device.approve",
        AfterDeviceApproveEvent(
            user_id=user_id,
            device_authorization=pending.authorization,
            request=request,
        ),
    )
    return True


def deny_device_authorization(
    context: Context, user_code: str, *, user_id: str
) -> bool:
    """Deny the request ``user_code`` belongs to; the device gets ``access_denied``.

    Returns False, and changes nothing, when no pending request has that
    code. Denying grants nothing, so ``user_can_authenticate`` is not asked.
    """
    pending = _find_pending(context, user_code)
    if pending is None:
        return False
    return _decide(context, pending, _Decision(approved=False, user_id=user_id))


def _expired() -> CrossAuthException:
    return CrossAuthException("expired_token", "The device code has expired")


def _check_poll_rate(
    storage: SecondaryStorage,
    device_hash: str,
    data: _DeviceRequestData,
    *,
    now: datetime,
    ttl: int,
) -> None:
    """Raise ``slow_down`` for a poll sooner than the interval after the last.

    The first poll is never too soon. ``get`` then ``set`` is not atomic, so
    two polls at the same moment may both pass; the decision is still popped
    once.
    """
    key = POLL_KEY.format(hash=device_hash)
    raw = storage.get(key)
    state = None
    if raw is not None:
        try:
            state = _PollState.model_validate_json(raw)
        except ValidationError:
            state = None
    interval = data.interval if state is None else state.interval
    too_soon = state is not None and now - state.last_polled_at < timedelta(
        seconds=interval
    )
    if too_soon:
        interval += _SLOW_DOWN_STEP
    storage.set(
        key,
        _PollState(last_polled_at=now, interval=interval).model_dump_json(),
        ttl=ttl,
    )
    if too_soon:
        raise CrossAuthException("slow_down", f"Wait {interval} seconds between polls")


def redeem_device_code(
    context: Context, *, client_id: str, device_code: str
) -> tuple[str, DeviceAuthorization]:
    """Answer one poll of ``/token``: the approving user and the request.

    Raises ``CrossAuthException`` with the RFC 8628 section 3.5 errors
    otherwise: ``authorization_pending`` until the user decides, ``slow_down``
    for a poll too soon, ``access_denied`` once denied, and ``expired_token``
    once the request expired or a poll consumed its decision. A device code
    issued to another client is ``invalid_grant``, and an unregistered client
    ``invalid_client``. Only the first poll after the decision returns, so
    there is one session per approval.
    """
    _device_grant(context)
    client = context.get_client(client_id)
    if client is None:
        raise CrossAuthException("invalid_client", "Unknown client")

    storage = context.secondary_storage
    device_hash = _hash(device_code)
    request_key = REQUEST_KEY.format(hash=device_hash)
    raw = storage.get(request_key)
    if raw is None:
        # Expired and evicted, ended by an earlier poll, or never issued:
        # stored only under its hash, a code can't tell these apart, and the
        # device must start again in each case.
        raise _expired()
    try:
        data = _DeviceRequestData.model_validate_json(raw)
    except ValidationError:
        raise _expired() from None
    if data.client_id != client_id:
        raise CrossAuthException(
            "invalid_grant", "The device code was issued to another client"
        )
    now = datetime.now(tz=timezone.utc)
    ttl = _seconds_left(data.expires_at, now)
    if ttl is None:
        raise _expired()
    _check_poll_rate(storage, device_hash, data, now=now, ttl=ttl)

    raw_decision = storage.pop(DECISION_KEY.format(hash=device_hash))
    if raw_decision is None:
        # Also while an approval is between taking the user code and storing
        # its decision: the request is still there, so it is still pending.
        raise CrossAuthException(
            "authorization_pending", "The user has not approved the request yet"
        )
    # This poll took the decision: end the request first, so every later poll
    # gets expired_token whatever happens to this one.
    storage.delete(request_key)
    storage.delete(POLL_KEY.format(hash=device_hash))
    try:
        decision = _Decision.model_validate_json(raw_decision)
    except ValidationError:
        raise _expired() from None
    if not decision.approved:
        raise CrossAuthException("access_denied", "The user denied the request")
    return decision.user_id, _authorization(data, client)


def _not_found() -> Response:
    return Response.error(
        "invalid_user_code",
        error_description="The code is unknown, expired or already used",
    )


def _decision_body(request: HTTPRequest) -> DeviceDecisionRequest | Response:
    try:
        return DeviceDecisionRequest.model_validate_json(request.body or b"")
    except ValidationError:
        return Response.error(
            "invalid_request", error_description="user_code is required"
        )


@_session_endpoint
def lookup_device_authorization(
    request: HTTPRequest, context: Context, current: ResolvedSession
) -> Response:
    """GET /device?user_code= — the pending request a user code belongs to."""
    user_code = request.query_params.get("user_code")
    if not user_code:
        return Response.error(
            "invalid_request", error_description="user_code is required"
        )
    authorization = get_device_authorization(context, user_code)
    if authorization is None:
        return _not_found()
    return _json(authorization)


@_session_endpoint
def approve_device_route(
    request: HTTPRequest, context: Context, current: ResolvedSession
) -> Response:
    """POST /device/approve — approve a request for the caller's user."""
    body = _decision_body(request)
    if isinstance(body, Response):
        return body
    try:
        approved = approve_device_authorization(
            context,
            body.user_code,
            user_id=str(current.record.user_id),
            request=request,
        )
    except CrossAuthException as e:
        return _hook_error(e)
    return Response(status_code=204) if approved else _not_found()


@_session_endpoint
def deny_device_route(
    request: HTTPRequest, context: Context, current: ResolvedSession
) -> Response:
    """POST /device/deny — deny a request; the device gets ``access_denied``."""
    body = _decision_body(request)
    if isinstance(body, Response):
        return body
    denied = deny_device_authorization(
        context, body.user_code, user_id=str(current.record.user_id)
    )
    return Response(status_code=204) if denied else _not_found()


def _responses(descriptions: dict[str, str]) -> dict[str, Any]:
    return {
        "responses": {
            status: {"description": description}
            for status, description in descriptions.items()
        }
    }


_DECISION_BODY: dict[str, Any] = {
    "requestBody": {
        "content": {
            "application/json": {"schema": DeviceDecisionRequest.model_json_schema()}
        },
        "required": True,
    }
}


def device_routes(*, approval: bool) -> list[Route]:
    """The device grant's routes; ``approval`` adds the signed-in user's ones.

    Those resolve the user from the request's session, as the session routes
    do, so they need ``session_storage``.
    """
    routes = [
        Route(
            path="/device/code",
            methods=["POST"],
            function=request_device_authorization,
            response_model=DeviceAuthorizationResponse,
            operation_id="device_authorization",
            read_form_data=True,
            summary="Start a device authorization request",
            openapi={
                "requestBody": {
                    "content": {
                        "application/x-www-form-urlencoded": {
                            "schema": {
                                "type": "object",
                                "title": "DeviceAuthorizationRequest",
                                "properties": {
                                    "client_id": {"type": "string"},
                                    "scope": {"type": "string"},
                                },
                                "required": ["client_id"],
                            }
                        }
                    },
                    "required": True,
                },
                **_responses({"400": "Unknown client or invalid request"}),
            },
        )
    ]
    if not approval:
        return routes
    return [
        *routes,
        Route(
            path="/device",
            methods=["GET"],
            function=lookup_device_authorization,
            response_model=DeviceAuthorization,
            operation_id="get_device_authorization",
            summary="Look up a pending device authorization request",
            openapi={
                "parameters": [
                    {
                        "name": "user_code",
                        "in": "query",
                        "required": True,
                        "schema": {"type": "string", "title": "User Code"},
                        "description": "The code the device showed",
                    }
                ],
                **_responses(
                    {
                        "400": "No pending request has this code",
                        "401": "Not logged in",
                    }
                ),
            },
        ),
        Route(
            path="/device/approve",
            methods=["POST"],
            function=approve_device_route,
            status_code=204,
            operation_id="approve_device_authorization",
            summary="Approve a device authorization request",
            read_body=True,
            openapi={
                **_DECISION_BODY,
                **_responses(
                    {
                        "400": "No pending request has this code",
                        "401": "Not logged in",
                        "403": "The user may not sign in",
                    }
                ),
            },
        ),
        Route(
            path="/device/deny",
            methods=["POST"],
            function=deny_device_route,
            status_code=204,
            operation_id="deny_device_authorization",
            summary="Deny a device authorization request",
            read_body=True,
            openapi={
                **_DECISION_BODY,
                **_responses(
                    {
                        "400": "No pending request has this code",
                        "401": "Not logged in",
                    }
                ),
            },
        ),
    ]
