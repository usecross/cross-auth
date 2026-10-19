from typing import Any, cast, get_args

import pytest

from cross_auth.hooks._types import _ALL_EVENT_NAMES, HookEventName
from cross_auth.hooks.registry import HookRegistry


def test_runtime_event_names_match_hook_event_name() -> None:
    assert _ALL_EVENT_NAMES == frozenset(get_args(HookEventName))


def test_dispatch_rejects_unsupported_event_names() -> None:
    hooks = HookRegistry()
    invalid_event = cast(Any, "unsupported")

    with pytest.raises(ValueError, match="Unsupported hook event: unsupported"):
        hooks.run_before(invalid_event, object())

    with pytest.raises(ValueError, match="Unsupported hook event: unsupported"):
        hooks.run_after(invalid_event, object())


def test_empty_dispatch_does_not_create_handler_buckets() -> None:
    hooks = HookRegistry()
    payload = object()

    assert hooks.run_before("login", payload) is payload
    hooks.run_after("login", payload)

    assert hooks._before == {}
    assert hooks._after == {}
