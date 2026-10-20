"""Receivers tests program per test through ``handlers``."""

from collections.abc import Callable
from typing import Any

from django.dispatch import receiver

from cross_auth.django.signals import (
    after_login,
    authorization_started,
    before_authorization,
    before_callback,
    before_login,
    before_social_account_create,
    before_social_account_disconnect,
    before_social_account_update,
    before_user_create,
    social_account_created,
    social_account_disconnected,
    social_account_linked,
    social_account_updated,
    user_created,
)

events: list[tuple[str, dict[str, Any]]] = []
handlers: dict[str, Callable[..., object]] = {}


def _record(name: str, sender: object, kwargs: dict[str, Any]) -> object:
    events.append((name, {"sender": sender, **kwargs}))
    if handler := handlers.get(name):
        return handler(sender=sender, **kwargs)
    return None


@receiver(before_authorization)
def on_before_authorization(sender: object, **kwargs: Any) -> object:
    return _record("before_authorization", sender, kwargs)


@receiver(authorization_started)
def on_authorization_started(sender: object, **kwargs: Any) -> object:
    return _record("authorization_started", sender, kwargs)


@receiver(before_callback)
def on_before_callback(sender: object, **kwargs: Any) -> object:
    return _record("before_callback", sender, kwargs)


@receiver(before_user_create)
def on_before_user_create(sender: object, **kwargs: Any) -> object:
    return _record("before_user_create", sender, kwargs)


@receiver(user_created)
def on_user_created(sender: object, **kwargs: Any) -> object:
    return _record("user_created", sender, kwargs)


@receiver(before_social_account_create)
def on_before_social_account_create(sender: object, **kwargs: Any) -> object:
    return _record("before_social_account_create", sender, kwargs)


@receiver(social_account_created)
def on_social_account_created(sender: object, **kwargs: Any) -> object:
    return _record("social_account_created", sender, kwargs)


@receiver(before_social_account_update)
def on_before_social_account_update(sender: object, **kwargs: Any) -> object:
    return _record("before_social_account_update", sender, kwargs)


@receiver(social_account_updated)
def on_social_account_updated(sender: object, **kwargs: Any) -> object:
    return _record("social_account_updated", sender, kwargs)


@receiver(social_account_linked)
def on_social_account_linked(sender: object, **kwargs: Any) -> object:
    return _record("social_account_linked", sender, kwargs)


@receiver(before_login)
def on_before_login(sender: object, **kwargs: Any) -> object:
    return _record("before_login", sender, kwargs)


@receiver(after_login)
def on_after_login(sender: object, **kwargs: Any) -> object:
    return _record("after_login", sender, kwargs)


@receiver(before_social_account_disconnect)
def on_before_social_account_disconnect(sender: object, **kwargs: Any) -> object:
    return _record("before_social_account_disconnect", sender, kwargs)


@receiver(social_account_disconnected)
def on_social_account_disconnected(sender: object, **kwargs: Any) -> object:
    return _record("social_account_disconnected", sender, kwargs)
