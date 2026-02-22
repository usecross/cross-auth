from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Literal, TypedDict

from cross_web import AsyncHTTPRequest, Cookie
from pydantic import AwareDatetime, BaseModel

from ._storage import AccountsStorage, SecondaryStorage, User

_SESSION_KEY_PREFIX = "session:"
_DEFAULT_MAX_AGE = 86400


class SessionData(BaseModel):
    user_id: str
    created_at: AwareDatetime
    expires_at: AwareDatetime


class SessionConfig(TypedDict, total=False):
    cookie_name: str
    max_age: int
    secure: bool
    httponly: bool
    samesite: Literal["lax", "strict", "none"]
    path: str
    domain: str | None


_SESSION_CONFIG_DEFAULTS: SessionConfig = {
    "cookie_name": "session_id",
    "max_age": _DEFAULT_MAX_AGE,
    "secure": True,
    "httponly": True,
    "samesite": "lax",
    "path": "/",
    "domain": None,
}


def resolve_config(config: SessionConfig | None) -> SessionConfig:
    if config is None:
        return _SESSION_CONFIG_DEFAULTS
    return {**_SESSION_CONFIG_DEFAULTS, **config}


def create_session(
    user_id: str,
    storage: SecondaryStorage,
    max_age: int = _DEFAULT_MAX_AGE,
) -> tuple[str, SessionData]:
    session_id = secrets.token_urlsafe(32)
    now = datetime.now(tz=timezone.utc)
    session_data = SessionData(
        user_id=user_id,
        created_at=now,
        expires_at=now + timedelta(seconds=max_age),
    )
    storage.set(f"{_SESSION_KEY_PREFIX}{session_id}", session_data.model_dump_json())
    return session_id, session_data


def get_session(
    session_id: str,
    storage: SecondaryStorage,
) -> SessionData | None:
    raw = storage.get(f"{_SESSION_KEY_PREFIX}{session_id}")
    if raw is None:
        return None
    session = SessionData.model_validate_json(raw)
    if datetime.now(tz=timezone.utc) > session.expires_at:
        storage.delete(f"{_SESSION_KEY_PREFIX}{session_id}")
        return None
    return session


def delete_session(
    session_id: str,
    storage: SecondaryStorage,
) -> None:
    try:
        storage.delete(f"{_SESSION_KEY_PREFIX}{session_id}")
    except KeyError:
        # MemoryStorage.delete raises KeyError for missing keys;
        # silently ignore since the goal is to ensure the session is gone.
        pass


def _build_cookie(
    value: str,
    max_age: int,
    resolved: SessionConfig,
) -> Cookie:
    return Cookie(
        name=resolved["cookie_name"],
        value=value,
        secure=resolved["secure"],
        path=resolved["path"],
        domain=resolved["domain"],
        max_age=max_age,
        httponly=resolved["httponly"],
        samesite=resolved["samesite"],
    )


def make_session_cookie(
    session_id: str,
    config: SessionConfig | None = None,
) -> Cookie:
    resolved = resolve_config(config)
    return _build_cookie(session_id, resolved["max_age"], resolved)


def make_clear_cookie(
    config: SessionConfig | None = None,
) -> Cookie:
    return _build_cookie("", 0, resolve_config(config))


def get_current_user(
    request: AsyncHTTPRequest,
    storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    config: SessionConfig | None = None,
) -> User | None:
    resolved = resolve_config(config)
    session_id = request.cookies.get(resolved["cookie_name"])
    if session_id is None:
        return None
    session = get_session(session_id, storage)
    if session is None:
        return None
    return accounts_storage.find_user_by_id(session.user_id)
