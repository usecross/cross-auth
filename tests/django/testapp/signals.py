"""Receivers tests program per test through ``handlers``."""

from collections.abc import Callable
from typing import Any

from django.dispatch import receiver

from cross_auth.django.signals import (
    after_login,
    before_login,
    before_user_create,
    user_created,
)

events: list[tuple[str, dict[str, Any]]] = []
handlers: dict[str, Callable[..., object]] = {}


def _record(name: str, sender: object, kwargs: dict[str, Any]) -> object:
    events.append((name, {"sender": sender, **kwargs}))
    if handler := handlers.get(name):
        return handler(sender=sender, **kwargs)
    return None


@receiver(before_user_create)
def on_before_user_create(sender: object, **kwargs: Any) -> object:
    return _record("before_user_create", sender, kwargs)


@receiver(user_created)
def on_user_created(sender: object, **kwargs: Any) -> object:
    return _record("user_created", sender, kwargs)


@receiver(before_login)
def on_before_login(sender: object, **kwargs: Any) -> object:
    return _record("before_login", sender, kwargs)


@receiver(after_login)
def on_after_login(sender: object, **kwargs: Any) -> object:
    return _record("after_login", sender, kwargs)
