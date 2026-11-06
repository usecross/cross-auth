"""Database ownership for native-user creation without changing factory calls."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

from django.contrib.auth import get_user_model
from django.db import router

_creation_database: ContextVar[str | None] = ContextVar(
    "cross_auth_creation_database", default=None
)


def user_database() -> str:
    """Database a user factory must use for all of its transactional writes.

    During signup this is the accounts storage's captured write alias. Outside
    signup it follows the user model's write router. Custom factories can pass
    it to ``db_manager()``/``using()`` without accepting another argument.
    """
    return _creation_database.get() or router.db_for_write(get_user_model())


@contextmanager
def creating_user_on(alias: str) -> Iterator[None]:
    token = _creation_database.set(alias)
    try:
        yield
    finally:
        _creation_database.reset(token)
