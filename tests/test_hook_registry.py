from typing import Any, cast

import pytest

from cross_auth.exceptions import CrossAuthException
from cross_auth.hooks.registry import HookRegistry


def test_dispatch_rejects_unsupported_event_names() -> None:
    hooks = HookRegistry()
    invalid_event = cast(Any, "unsupported")

    with pytest.raises(ValueError, match="Unsupported hook event: unsupported"):
        hooks.run_before(invalid_event, object())

    with pytest.raises(ValueError, match="Unsupported hook event: unsupported"):
        hooks.run_after(invalid_event, object())


def test_removed_session_issue_event_is_rejected() -> None:
    hooks = HookRegistry()
    removed = cast(Any, "session.issue")

    with pytest.raises(ValueError, match="Unsupported hook event: session.issue"):
        hooks.register_before(removed, lambda event: None)
    with pytest.raises(ValueError, match="Unsupported hook event: session.issue"):
        hooks.register_after(removed, lambda event: None)
    with pytest.raises(ValueError, match="Unsupported hook event: session.issue"):
        hooks.run_before(removed, object())


def test_after_hook_errors_propagate_and_stop_later_handlers() -> None:
    hooks = HookRegistry()
    calls: list[str] = []

    def fail(event: object) -> None:
        calls.append("fail")
        raise CrossAuthException("server_error")

    hooks.register_after("login", fail)
    hooks.register_after("login", lambda event: calls.append("later"))

    with pytest.raises(CrossAuthException):
        hooks.run_after("login", object())
    assert calls == ["fail"]


def test_empty_dispatch_preserves_payload() -> None:
    hooks = HookRegistry()
    payload = object()

    assert hooks.run_before("login", payload) is payload
    assert hooks.run_after("login", payload) is None
