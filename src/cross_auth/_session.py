from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Literal, TypedDict

from cross_web import AsyncHTTPRequest, Cookie
from pydantic import AwareDatetime, BaseModel

from ._password import DUMMY_PASSWORD_HASH, pwd_context
from ._storage import AccountsStorage, SecondaryStorage, User


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
    "max_age": 86400,
    "secure": True,
    "httponly": True,
    "samesite": "lax",
    "path": "/",
    "domain": None,
}


def _resolve_config(config: SessionConfig | None) -> SessionConfig:
    if config is None:
        return _SESSION_CONFIG_DEFAULTS
    return {**_SESSION_CONFIG_DEFAULTS, **config}  # type: ignore[typeddict-item]


def authenticate(
    email: str,
    password: str,
    accounts_storage: AccountsStorage,
) -> User | None:
    user = accounts_storage.find_user_by_email(email)

    if user is not None:
        valid = pwd_context.verify(
            password, user.hashed_password or DUMMY_PASSWORD_HASH
        )
    else:
        pwd_context.verify(password, DUMMY_PASSWORD_HASH)
        valid = False

    if not valid:
        return None

    return user


def create_session(
    user_id: str,
    storage: SecondaryStorage,
    max_age: int = 86400,
) -> tuple[str, SessionData]:
    session_id = secrets.token_urlsafe(32)
    now = datetime.now(tz=timezone.utc)
    session_data = SessionData(
        user_id=user_id,
        created_at=now,
        expires_at=now + timedelta(seconds=max_age),
    )
    storage.set(f"session:{session_id}", session_data.model_dump_json())
    return session_id, session_data


def get_session(
    session_id: str,
    storage: SecondaryStorage,
) -> SessionData | None:
    raw = storage.get(f"session:{session_id}")
    if raw is None:
        return None
    session = SessionData.model_validate_json(raw)
    if datetime.now(tz=timezone.utc) > session.expires_at:
        storage.delete(f"session:{session_id}")
        return None
    return session


def delete_session(
    session_id: str,
    storage: SecondaryStorage,
) -> None:
    try:
        storage.delete(f"session:{session_id}")
    except KeyError:
        pass


def make_session_cookie(
    session_id: str,
    config: SessionConfig | None = None,
) -> Cookie:
    resolved = _resolve_config(config)
    return Cookie(
        name=resolved["cookie_name"],
        value=session_id,
        secure=resolved["secure"],
        path=resolved["path"],
        domain=resolved.get("domain"),
        max_age=resolved["max_age"],
        httponly=resolved["httponly"],
        samesite=resolved["samesite"],
    )


def get_current_user(
    request: AsyncHTTPRequest,
    storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    config: SessionConfig | None = None,
) -> User | None:
    resolved = _resolve_config(config)
    session_id = request.cookies.get(resolved["cookie_name"])
    if session_id is None:
        return None
    session = get_session(session_id, storage)
    if session is None:
        return None
    return accounts_storage.find_user_by_id(session.user_id)


def make_clear_cookie(
    config: SessionConfig | None = None,
) -> Cookie:
    resolved = _resolve_config(config)
    return Cookie(
        name=resolved["cookie_name"],
        value="",
        secure=resolved["secure"],
        path=resolved["path"],
        domain=resolved.get("domain"),
        max_age=0,
        httponly=resolved["httponly"],
        samesite=resolved["samesite"],
    )
