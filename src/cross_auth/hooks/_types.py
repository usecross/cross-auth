from __future__ import annotations

from collections.abc import Callable
from typing import Literal, TypeAlias, get_args

HookEventName: TypeAlias = Literal[
    "authenticate",
    "login",
    "logout",
    "session.issue",
    "user.create",
    "social_account.create",
    "social_account.update",
    "oauth.authorize",
    "oauth.callback",
    "oauth.id_token",
    "oauth.link",
    "oauth.finalize_link",
    "oauth.disconnect",
    "token.password",
    "token.authorization_code",
]

_ALL_EVENT_NAMES: frozenset[str] = frozenset(get_args(HookEventName))
_RETURNABLE_BEFORE_EVENT_NAMES: frozenset[str] = frozenset(
    {
        "authenticate",
        "login",
        "logout",
        "session.issue",
        "user.create",
        "social_account.create",
        "social_account.update",
        "oauth.authorize",
        "oauth.callback",
        "oauth.id_token",
        "oauth.finalize_link",
    }
)

_BeforeRuntimeHandler: TypeAlias = Callable[[object], object | None]
_AfterRuntimeHandler: TypeAlias = Callable[[object], None]
