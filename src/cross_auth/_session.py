from __future__ import annotations

import hashlib
import ipaddress
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Literal, TypedDict

from cross_web import Cookie, HTTPRequest

from ._request import get_header
from ._storage import AccountsStorage, SessionRecord, SessionStorage, User
from ._token_format import generate_token

_DEFAULT_MAX_AGE = 86400
_USER_AGENT_MAX_LENGTH = 512
_CLIENT_MAX_LENGTH = 255

SessionTokenHasher = Callable[[str], str]
# Whether a user may sign in and keep using their sessions.
UserCanAuthenticate = Callable[[User], bool]


class SessionMetadata(TypedDict, total=False):
    client_id: str | None
    client_name: str | None
    user_agent: str | None
    ip: str | None


class SessionCookieConfig(TypedDict, total=False):
    # If True, register GET /{provider}/login and complete OAuth callbacks
    # into a browser session cookie. Requires session_storage. When False
    # (default), the login routes are not registered. The OAuth server's
    # token/PKCE routes are configured separately through OAuthServer.
    auth: bool
    name: str
    secure: bool
    httponly: bool
    samesite: Literal["lax", "strict", "none"]
    path: str
    domain: str | None


class SessionConfig(TypedDict, total=False):
    max_age: int
    update_age: int | None
    token_hasher: SessionTokenHasher
    # If set, new session tokens are "{token_prefix}_" plus 32 base62
    # characters and a checksum. Lookups accept any token, so sessions issued
    # before the prefix was set keep working.
    token_prefix: str | None
    # If True (default), sessions store the client's IP address: Cross-Auth's
    # own routes read it from the request, and other logins can pass it in
    # metadata. If False, no session stores an IP, even one passed in
    # metadata or set by a login hook.
    store_ip: bool
    cookies: SessionCookieConfig


_SESSION_COOKIE_DEFAULTS: SessionCookieConfig = {
    "auth": False,
    "name": "session_id",
    "secure": True,
    "httponly": True,
    "samesite": "lax",
    "path": "/",
    "domain": None,
}

_SESSION_CONFIG_DEFAULTS: SessionConfig = {
    "max_age": _DEFAULT_MAX_AGE,
    "update_age": None,
    "token_hasher": lambda session_token: hashlib.sha256(
        session_token.encode("utf-8")
    ).hexdigest(),
    "token_prefix": None,
    "store_ip": True,
    "cookies": _SESSION_COOKIE_DEFAULTS,
}


def resolve_config(config: SessionConfig | None) -> SessionConfig:
    base: SessionConfig = config if config is not None else {}
    return {
        **_SESSION_CONFIG_DEFAULTS,
        **base,
        "cookies": {**_SESSION_COOKIE_DEFAULTS, **base.get("cookies", {})},
    }


def hash_session_token(
    session_token: str,
    token_hasher: SessionTokenHasher | None = None,
) -> str:
    hasher = token_hasher or _SESSION_CONFIG_DEFAULTS["token_hasher"]
    return hasher(session_token)


def _clean_text(value: str | None, *, max_length: int) -> str | None:
    """Return ``value`` fit to store and show, or ``None``.

    Control and other unprintable characters become spaces (PostgreSQL also
    refuses NUL), runs of whitespace collapse, and the result is cut to
    ``max_length`` characters.
    """
    if not value:
        return None

    cleaned: list[str] = []
    for char in value:
        if char.isprintable() and not char.isspace():
            cleaned.append(char)
        elif cleaned and cleaned[-1] != " ":
            cleaned.append(" ")
        if len(cleaned) == max_length:
            break

    return "".join(cleaned).rstrip() or None


def clean_user_agent(value: str | None) -> str | None:
    """Return a user agent fit to store and show, or ``None``."""
    return _clean_text(value, max_length=_USER_AGENT_MAX_LENGTH)


def clean_ip(value: str | None) -> str | None:
    """Return the normalized IP address in ``value``, or ``None``.

    IPv6 zone IDs are dropped and IPv4-mapped IPv6 addresses become IPv4.
    """
    if not value:
        return None

    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return None

    if isinstance(address, ipaddress.IPv6Address):
        # ipaddress accepts arbitrary scope strings, including address lists.
        if address.scope_id is not None and any(
            not char.isprintable() or char.isspace() or char in ",/[]"
            for char in address.scope_id
        ):
            return None
        address = ipaddress.IPv6Address(int(address))
        if address.ipv4_mapped:
            return str(address.ipv4_mapped)
    return str(address)


def clean_session_metadata(metadata: SessionMetadata | None) -> SessionMetadata:
    """Return ``metadata`` fit to store and show.

    Clients choose most of it, and session lists show it back to users.
    ``client_id`` and ``client_name`` are cleaned like a user agent but cut
    to 255 characters; an ``ip`` that is not a single IP address is dropped.
    """
    values = metadata or {}
    return {
        "client_id": _clean_text(
            values.get("client_id"), max_length=_CLIENT_MAX_LENGTH
        ),
        "client_name": _clean_text(
            values.get("client_name"), max_length=_CLIENT_MAX_LENGTH
        ),
        "user_agent": clean_user_agent(values.get("user_agent")),
        "ip": clean_ip(values.get("ip")),
    }


def request_metadata(
    request: HTTPRequest, config: SessionConfig | None = None
) -> SessionMetadata:
    """Return the session metadata ``request`` carries.

    That is its user agent and, unless ``store_ip`` is off, its client
    address as the framework reports it. Behind a proxy, that is the proxy's
    address unless the server trusts the proxy's forwarded headers.
    """
    metadata: SessionMetadata = {
        "user_agent": get_header(request.headers, "user-agent")
    }
    if resolve_config(config)["store_ip"]:
        metadata["ip"] = request.client_host
    return metadata


def create_session(
    user_id: str,
    storage: SessionStorage,
    max_age: int = _DEFAULT_MAX_AGE,
    *,
    metadata: SessionMetadata | None = None,
    token_hasher: SessionTokenHasher | None = None,
    token_prefix: str | None = None,
    login_method: str | None = None,
    store_ip: bool = True,
) -> tuple[str, SessionRecord]:
    session_token = (
        secrets.token_urlsafe(32)
        if token_prefix is None
        else generate_token(token_prefix)
    )
    now = datetime.now(tz=timezone.utc)
    expires_at = now + timedelta(seconds=max_age)
    cleaned_metadata = clean_session_metadata(metadata)
    session_record = storage.create(
        token_hash=hash_session_token(session_token, token_hasher),
        user_id=user_id,
        created_at=now,
        updated_at=now,
        expires_at=expires_at,
        client_id=cleaned_metadata["client_id"],
        client_name=cleaned_metadata["client_name"],
        user_agent=cleaned_metadata["user_agent"],
        ip=cleaned_metadata["ip"] if store_ip else None,
        last_active_at=now,
        login_method=login_method,
    )
    return session_token, session_record


def get_session(
    session_token: str,
    storage: SessionStorage,
    config: SessionConfig | None = None,
) -> SessionRecord | None:
    result = _get_session(session_token, storage, resolve_config(config))
    return result[0] if result is not None else None


@dataclass(frozen=True)
class AuthenticatedSession:
    """An active session and the user it belongs to."""

    session: SessionRecord
    user: User


def authenticate_session_token(
    session_token: str,
    storage: SessionStorage,
    accounts_storage: AccountsStorage,
    config: SessionConfig | None = None,
    *,
    user_can_authenticate: UserCanAuthenticate | None = None,
) -> AuthenticatedSession | None:
    """Return the active session ``session_token`` belongs to and its user.

    Returns ``None`` when the token is unknown, revoked or expired, when the
    user is not found, or when ``user_can_authenticate`` returns False; a
    ``CrossAuthException`` it raises propagates. The user is checked before a
    sliding refresh, so a refused token does not extend its session.
    """
    resolved = resolve_config(config)
    session = _find_session(session_token, storage, resolved)
    if session is None:
        return None
    user = _session_user(session, accounts_storage, user_can_authenticate)
    if user is None:
        return None
    result = _refresh_session(session, storage, resolved)
    if result is None:
        return None
    return AuthenticatedSession(result[0], user)


def _session_user(
    session: SessionRecord,
    accounts_storage: AccountsStorage,
    user_can_authenticate: UserCanAuthenticate | None,
) -> User | None:
    """Return the user of ``session``, or ``None`` if it may not use it."""
    user = accounts_storage.find_user_by_id(session.user_id)
    if user is None:
        return None
    if user_can_authenticate is not None and not user_can_authenticate(user):
        return None
    return user


def _find_session(
    session_token: str, storage: SessionStorage, resolved: SessionConfig
) -> SessionRecord | None:
    """Look up the active session ``session_token`` belongs to, without refreshing it."""
    return storage.get(
        token_hash=hash_session_token(session_token, resolved["token_hasher"]),
        now=datetime.now(tz=timezone.utc),
    )


def _get_session(
    session_token: str,
    storage: SessionStorage,
    resolved: SessionConfig,
    *,
    refresh: bool = True,
) -> tuple[SessionRecord, bool] | None:
    """Resolve a session by token, returning (record, refreshed).

    See ``_refresh_session`` for ``refreshed``.
    """
    session = _find_session(session_token, storage, resolved)
    if session is None:
        return None
    if not refresh:
        return session, False
    return _refresh_session(session, storage, resolved)


def _refresh_session(
    session: SessionRecord, storage: SessionStorage, resolved: SessionConfig
) -> tuple[SessionRecord, bool] | None:
    """Roll ``session`` forward once its ``update_age`` window elapsed.

    Returns (record, refreshed), or ``None`` if the session ended before the
    refresh. ``refreshed`` is True when the record was rolled forward
    (extending ``expires_at``); callers serving cookies use it to decide
    whether to reissue Set-Cookie with a fresh Max-Age.
    """
    update_age = resolved.get("update_age")
    if update_age is None:
        return session, False

    now = datetime.now(tz=timezone.utc)
    if now - session.updated_at < timedelta(seconds=update_age):
        return session, False

    refreshed = storage.refresh(
        session.id,
        updated_at=now,
        expires_at=now + timedelta(seconds=resolved["max_age"]),
        last_active_at=now,
    )
    if refreshed is None:
        return None
    # A concurrent refresh that got there first comes back unchanged, with a
    # later updated_at; its expiry did not move, so there is no cookie to roll.
    return refreshed, refreshed.updated_at <= now


def get_user_session(
    session_id: object, storage: SessionStorage, *, user_id: object
) -> SessionRecord | None:
    """Return the session ``session_id`` if ``user_id`` owns it, in any status.

    Another user's session answers ``None``, like a missing one, so a caller
    cannot tell the two apart.
    """
    session = storage.get_any(session_id)
    if session is None or str(session.user_id) != str(user_id):
        return None
    return session


def delete_session(
    session_token: str,
    storage: SessionStorage,
    config: SessionConfig | None = None,
) -> None:
    resolved = resolve_config(config)
    now = datetime.now(tz=timezone.utc)
    session = storage.get(
        token_hash=hash_session_token(session_token, resolved["token_hasher"]),
        now=now,
    )
    if session is not None:
        storage.revoke(session.id, revoked_at=now)


def _build_cookie(
    value: str,
    max_age: int,
    resolved: SessionConfig,
) -> Cookie:
    cookies = resolved["cookies"]
    return Cookie(
        name=cookies["name"],
        value=value,
        secure=cookies["secure"],
        path=cookies["path"],
        domain=cookies["domain"],
        max_age=max_age,
        httponly=cookies["httponly"],
        samesite=cookies["samesite"],
    )


def make_session_cookie(
    session_token: str,
    config: SessionConfig | None = None,
) -> Cookie:
    resolved = resolve_config(config)
    return _build_cookie(session_token, resolved["max_age"], resolved)


def make_clear_cookie(
    config: SessionConfig | None = None,
) -> Cookie:
    return _build_cookie("", 0, resolve_config(config))


def get_current_user(
    request: HTTPRequest,
    storage: SessionStorage,
    accounts_storage: AccountsStorage,
    config: SessionConfig | None = None,
    *,
    user_can_authenticate: UserCanAuthenticate | None = None,
) -> User | None:
    """Return the user of the request's session, or ``None``.

    A session whose user is not found, or refused by ``user_can_authenticate``,
    counts as no session; a ``CrossAuthException`` it raises propagates.
    """
    resolution = resolve_current_session(
        request,
        storage,
        config,
        accounts_storage=accounts_storage,
        user_can_authenticate=user_can_authenticate,
    )
    return None if resolution is None else resolution.user


@dataclass(frozen=True)
class ResolvedSession:
    record: SessionRecord
    token: str
    source: Literal["cookie", "bearer"]
    refreshed: bool
    # Set when the session was resolved with an accounts storage.
    user: User | None = None


def resolve_current_session(
    request: HTTPRequest,
    storage: SessionStorage,
    config: SessionConfig | None = None,
    *,
    refresh: bool = True,
    accounts_storage: AccountsStorage | None = None,
    user_can_authenticate: UserCanAuthenticate | None = None,
) -> ResolvedSession | None:
    """Resolve the request's session, preferring the cookie over a bearer token.

    Unlike ``get_current_session`` this also reports the transport the token
    arrived on and whether the record was just refreshed, so a response-aware
    caller can roll the session cookie forward. Set ``refresh=False`` when
    resolving a session for logout so it is not extended before revocation.

    With ``accounts_storage`` it also loads the session's user, before any
    refresh: if the user is not found, or refused by ``user_can_authenticate``,
    the request has no session, so a refused request does not extend it. The
    session found first still decides: a bearer token is not tried instead.
    A ``CrossAuthException`` the check raises propagates.
    """
    resolved = resolve_config(config)

    candidates: tuple[tuple[Literal["cookie", "bearer"], str | None], ...] = (
        ("cookie", request.cookies.get(resolved["cookies"]["name"])),
        ("bearer", get_bearer_token(request)),
    )
    for source, token in candidates:
        if token is None:
            continue
        session = _find_session(token, storage, resolved)
        if session is None:
            continue
        user = None
        if accounts_storage is not None:
            user = _session_user(session, accounts_storage, user_can_authenticate)
            if user is None:
                return None
        result = (
            _refresh_session(session, storage, resolved)
            if refresh
            else (session, False)
        )
        if result is not None:
            record, refreshed = result
            return ResolvedSession(record, token, source, refreshed, user)

    return None


def get_current_session(
    request: HTTPRequest,
    storage: SessionStorage,
    config: SessionConfig | None = None,
) -> SessionRecord | None:
    resolution = resolve_current_session(request, storage, config)
    return resolution.record if resolution is not None else None


def get_bearer_token(request: HTTPRequest) -> str | None:
    """Extract a bearer credential without validating the token or its owner."""
    authorization = get_header(request.headers, "authorization")
    if authorization is None:
        return None

    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer":
        return None
    return token.strip() or None
