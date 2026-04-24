from __future__ import annotations

import inspect
import logging
from collections import defaultdict
from collections.abc import Awaitable, Callable
from typing import TypeAlias, TypeVar, cast

from ..exceptions import CrossAuthException
from ._types import (
    _ALL_EVENT_NAMES,
    _RETURNABLE_BEFORE_EVENT_NAMES,
    _SYNC_EVENT_NAMES,
    HookEventName,
)

logger = logging.getLogger(__name__)

_BeforeRuntimeHandler: TypeAlias = Callable[
    [object], object | Awaitable[object | None] | None
]
_AfterRuntimeHandler: TypeAlias = Callable[[object], Awaitable[None] | None]
_EventT = TypeVar("_EventT")


class HookRegistry:
    def __init__(self) -> None:
        self._before: defaultdict[str, list[_BeforeRuntimeHandler]] = defaultdict(list)
        self._after: defaultdict[str, list[_AfterRuntimeHandler]] = defaultdict(list)

    def register_before(
        self,
        event: HookEventName,
        handler: Callable[..., object],
        *,
        allow_async: bool,
    ) -> None:
        self._validate_event_name(event)
        self._validate_sync_registration(event, handler, allow_async=allow_async)
        self._before[event].append(cast(_BeforeRuntimeHandler, handler))

    def register_after(
        self,
        event: HookEventName,
        handler: Callable[..., object],
        *,
        allow_async: bool,
    ) -> None:
        self._validate_event_name(event)
        self._validate_sync_registration(event, handler, allow_async=allow_async)
        self._after[event].append(cast(_AfterRuntimeHandler, handler))

    def run_before(self, event: HookEventName, payload: _EventT) -> _EventT:
        current = payload

        for handler in self._before[event]:
            result = handler(current)
            if inspect.isawaitable(result):
                raise TypeError(f"{event} hooks for sync events must be synchronous")
            current = self._resolve_before_result(event, current, result)

        return current

    async def run_before_async(self, event: HookEventName, payload: _EventT) -> _EventT:
        current = payload

        for handler in self._before[event]:
            result = handler(current)
            if inspect.isawaitable(result):
                result = await result
            current = self._resolve_before_result(event, current, result)

        return current

    def run_after(self, event: HookEventName, payload: _EventT) -> None:
        for handler in self._after[event]:
            try:
                result = handler(payload)
                if inspect.isawaitable(result):
                    raise TypeError(
                        f"{event} hooks for sync events must be synchronous"
                    )
                if result is not None:
                    raise TypeError(f"{event} after hooks must return None")
            except CrossAuthException:
                logger.warning(
                    "Ignoring CrossAuthException raised by after hook for %s",
                    event,
                    exc_info=True,
                )

    async def run_after_async(self, event: HookEventName, payload: _EventT) -> None:
        for handler in self._after[event]:
            try:
                result = handler(payload)
                if inspect.isawaitable(result):
                    result = await result
                if result is not None:
                    raise TypeError(f"{event} after hooks must return None")
            except CrossAuthException:
                logger.warning(
                    "Ignoring CrossAuthException raised by after hook for %s",
                    event,
                    exc_info=True,
                )

    @staticmethod
    def _validate_sync_registration(
        event: HookEventName,
        handler: Callable[..., object],
        *,
        allow_async: bool,
    ) -> None:
        if allow_async:
            return
        if inspect.iscoroutinefunction(handler):
            raise TypeError(f"{event} hooks for sync events must be synchronous")

    @staticmethod
    def _validate_event_name(event: str) -> None:
        if event not in _ALL_EVENT_NAMES:
            raise ValueError(f"Unsupported hook event: {event}")

    @staticmethod
    def _resolve_before_result(
        event: HookEventName,
        payload: _EventT,
        result: object | None,
    ) -> _EventT:
        if result is None:
            return payload

        if event not in _RETURNABLE_BEFORE_EVENT_NAMES:
            raise TypeError(f"{event} before hooks must return None")

        if type(result) is not type(payload):
            raise TypeError(
                f"{event} before hooks must return {type(payload).__name__} or None"
            )

        return cast(_EventT, result)


def _event_allows_async(event: HookEventName) -> bool:
    return event not in _SYNC_EVENT_NAMES


__all__ = ["HookRegistry"]
