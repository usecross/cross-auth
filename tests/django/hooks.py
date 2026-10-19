"""A hook registry tests can program per test through ``handlers``."""

from collections.abc import Callable
from typing import Any

from cross_auth.hooks import (
    AfterLoginEvent,
    AfterUserCreateEvent,
    BeforeLoginEvent,
    HookRegistry,
)

hooks = HookRegistry()
events: list[tuple[str, Any]] = []
handlers: dict[str, Callable[[Any], None]] = {}


def before_login(event: BeforeLoginEvent) -> None:
    events.append(("before login", event))
    if handler := handlers.get("before login"):
        handler(event)


def after_login(event: AfterLoginEvent) -> None:
    events.append(("after login", event))
    if handler := handlers.get("after login"):
        handler(event)


def after_user_create(event: AfterUserCreateEvent) -> None:
    events.append(("after user.create", event))


hooks.register_before("login", before_login)
hooks.register_after("login", after_login)
hooks.register_after("user.create", after_user_create)
