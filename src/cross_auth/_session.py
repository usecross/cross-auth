from __future__ import annotations

import hashlib
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Literal, TypedDict

from cross_web import HTTPRequest, Cookie

from ._storage import AccountsStorage, SessionRecord, SessionStorage, User

_DEFAULT_MAX_AGE = 86400

SessionTokenHasher = Callable[[str], str]


class SessionMetadata(TypedDict, total=False):
    client_id: str | None
    client_name: str | None
    user_agent: str | None
    ip: str | None


class SessionCookieConfig(TypedDict, total=False):
    # If True, register GET /{provider}/login and complete OAuth callbacks
    # into a browser session cookie. Requires session_storage. When False
    # (default), the login routes are not registered and only the token/PKCE
    # flow (/authorize, /callback, /token) is exposed.
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
    "cookies": _SESSION_COOKIE_DEFAULTS,
}


def resolve_config(config: SessionConfig | None) -> SessionConfig:
    base: SessionConfig = config if config is not None else {}
    # Shallow-merge top level, but deep-merge the nested cookie attributes so a
    # partial `cookies` override doesn't drop the other cookie defaults.
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


def create_session(
    user_id: str,
    storage: SessionStorage,
    max_age: int = _DEFAULT_MAX_AGE,
    *,
    metadata: SessionMetadata | None = None,
    token_hasher: SessionTokenHasher | None = None,
) -> tuple[str, SessionRecord]:
    session_token = secrets.token_urlsafe(32)
    now = datetime.now(tz=timezone.utc)
    expires_at = now + timedelta(seconds=max_age)
    resolved_metadata = metadata or {}
    session_record = storage.create(
        token_hash=hash_session_token(session_token, token_hasher),
        user_id=user_id,
        created_at=now,
        updated_at=now,
        expires_at=expires_at,
        client_id=resolved_metadata.get("client_id"),
        client_name=resolved_metadata.get("client_name"),
        user_agent=resolved_metadata.get("user_agent"),
        ip=resolved_metadata.get("ip"),
        last_active_at=now,
    )
    return session_token, session_record


def get_session(
    session_token: str,
    storage: SessionStorage,
    config: SessionConfig | None = None,
) -> SessionRecord | None:
    result = _get_session(session_token, storage, resolve_config(config))
    return result[0] if result is not None else None


def _get_session(
    session_token: str,
    storage: SessionStorage,
    resolved: SessionConfig,
) -> tuple[SessionRecord, bool] | None:
    """Resolve a session by token, returning (record, refreshed).

    ``refreshed`` is True when the ``update_age`` window elapsed and the record
    was rolled forward (extending ``expires_at``); callers serving cookies use
    it to decide whether to reissue Set-Cookie with a fresh Max-Age.
    """
    now = datetime.now(tz=timezone.utc)
    session = storage.get(
        token_hash=hash_session_token(session_token, resolved["token_hasher"]),
        now=now,
    )
    if session is None:
        return None

    update_age = resolved.get("update_age")
    if update_age is None:
        return session, False

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
    return refreshed, True


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
) -> User | None:
    session = get_current_session(request, storage, config)
    if session is None:
        return None
    return accounts_storage.find_user_by_id(session.user_id)


@dataclass(frozen=True)
class ResolvedSession:
    record: SessionRecord
    token: str
    source: Literal["cookie", "bearer"]
    refreshed: bool


def resolve_current_session(
    request: HTTPRequest,
    storage: SessionStorage,
    config: SessionConfig | None = None,
) -> ResolvedSession | None:
    """Resolve the request's session, preferring the cookie over a bearer token.

    Unlike ``get_current_session`` this also reports the transport the token
    arrived on and whether the record was just refreshed, so a response-aware
    caller can roll the session cookie forward.
    """
    resolved = resolve_config(config)

    cookie_token = request.cookies.get(resolved["cookies"]["name"])
    if cookie_token is not None:
        result = _get_session(cookie_token, storage, resolved)
        if result is not None:
            record, refreshed = result
            return ResolvedSession(record, cookie_token, "cookie", refreshed)

    bearer_token = _get_bearer_token(request)
    if bearer_token is not None:
        result = _get_session(bearer_token, storage, resolved)
        if result is not None:
            record, refreshed = result
            return ResolvedSession(record, bearer_token, "bearer", refreshed)

    return None


def get_current_session(
    request: HTTPRequest,
    storage: SessionStorage,
    config: SessionConfig | None = None,
) -> SessionRecord | None:
    resolution = resolve_current_session(request, storage, config)
    return resolution.record if resolution is not None else None


def _get_bearer_token(request: HTTPRequest) -> str | None:
    authorization = _get_header(request.headers, "authorization")
    if authorization is None:
        return None

    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None
    return token.strip()


def _get_header(headers: Mapping[str, str], name: str) -> str | None:
    normalized = name.lower()
    for key, value in headers.items():
        if key.lower() == normalized:
            return value
    return None
