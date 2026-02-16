from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from inspect import isawaitable
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Literal, Protocol, TypedDict, cast

from ._storage import User

if TYPE_CHECKING:
    from .models.oauth_token_response import TokenResponse
    from .social_providers.oauth import OAuth2Provider

logger = logging.getLogger(__name__)

HookResult = object | Awaitable[object]
HookErrorMode = Literal["strict", "robust"]
HookFlow = Literal["login", "link"]
HookEvent = Literal[
    "before_token_exchange",
    "after_token_exchange",
    "before_user_info",
    "after_user_info",
    "before_account_link",
    "after_account_link",
    "after_login_code_issued",
]


class BeforeTokenExchangeHook(Protocol):
    def __call__(
        self,
        *,
        code: str,
        proxy_redirect_uri: str,
        provider_code_verifier: str | None,
        provider: OAuth2Provider,
        flow: HookFlow,
    ) -> HookResult: ...


class AfterTokenExchangeHook(Protocol):
    def __call__(
        self,
        *,
        token_response: TokenResponse,
        provider: OAuth2Provider,
        flow: HookFlow,
    ) -> HookResult: ...


class BeforeUserInfoHook(Protocol):
    def __call__(
        self,
        *,
        access_token: str,
        provider: OAuth2Provider,
        flow: HookFlow,
    ) -> HookResult: ...


class AfterUserInfoHook(Protocol):
    def __call__(
        self,
        *,
        user_info: Mapping[str, Any],
        access_token: str,
        provider: OAuth2Provider,
    ) -> HookResult: ...


class BeforeAccountLinkHook(Protocol):
    def __call__(
        self,
        *,
        user: User,
        provider: OAuth2Provider,
        provider_user_id: str,
        provider_email: str,
        flow: HookFlow,
        action: Literal["create", "update"],
        social_account_exists: bool,
        social_account_id: str | None,
    ) -> HookResult: ...


class AfterAccountLinkHook(Protocol):
    def __call__(
        self,
        *,
        user: User,
        provider: OAuth2Provider,
        provider_user_id: str,
        provider_email: str,
        flow: HookFlow,
        action: Literal["create", "update"],
        social_account_exists: bool,
        social_account_id: str,
    ) -> HookResult: ...


class AfterLoginCodeIssuedHook(Protocol):
    def __call__(
        self,
        *,
        code: str,
        user: User,
        provider: OAuth2Provider,
        client_id: str,
        redirect_uri: str,
    ) -> HookResult: ...


HookCallback = Callable[..., HookResult]


@dataclass(frozen=True, slots=True)
class HookRegistration:
    callback: HookCallback
    priority: int = 0
    timeout_seconds: float | None = None
    name: str | None = None
    source: str | None = None
    mode: HookErrorMode | None = None

    def __post_init__(self) -> None:
        if self.timeout_seconds is not None and self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than 0")

    @property
    def label(self) -> str:
        if self.name:
            return self.name

        return getattr(self.callback, "__name__", self.callback.__class__.__name__)

    @property
    def origin(self) -> str:
        if self.source:
            return self.source

        return getattr(self.callback, "__module__", "unknown")


HookInput = HookCallback | HookRegistration
HooksMapping = Mapping[str, Sequence[HookInput]]


class Hooks(TypedDict, total=False):
    before_token_exchange: list[BeforeTokenExchangeHook | HookRegistration]
    after_token_exchange: list[AfterTokenExchangeHook | HookRegistration]
    before_user_info: list[BeforeUserInfoHook | HookRegistration]
    after_user_info: list[AfterUserInfoHook | HookRegistration]
    before_account_link: list[BeforeAccountLinkHook | HookRegistration]
    after_account_link: list[AfterAccountLinkHook | HookRegistration]
    after_login_code_issued: list[AfterLoginCodeIssuedHook | HookRegistration]


class HookSettings(TypedDict, total=False):
    default_mode: HookErrorMode
    mode_by_event: dict[HookEvent, HookErrorMode]


@dataclass(frozen=True, slots=True)
class _StoredHook:
    registration: HookRegistration
    order: int


def _to_registration(hook: HookInput) -> HookRegistration:
    if isinstance(hook, HookRegistration):
        return hook

    return HookRegistration(callback=hook)


def _freeze_payload(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({k: _freeze_payload(v) for k, v in value.items()})

    if isinstance(value, list):
        return tuple(_freeze_payload(v) for v in value)

    if isinstance(value, tuple):
        return tuple(_freeze_payload(v) for v in value)

    if isinstance(value, set):
        return frozenset(_freeze_payload(v) for v in value)

    return value


class HookRegistry:
    def __init__(
        self,
        hooks: HooksMapping | None = None,
        settings: HookSettings | None = None,
    ) -> None:
        self.default_mode: HookErrorMode = "strict"
        self.mode_by_event: dict[str, HookErrorMode] = {}

        if settings is not None:
            self.default_mode = settings.get("default_mode", "strict")
            self.mode_by_event = dict(settings.get("mode_by_event", {}))

        self._hooks: dict[str, list[_StoredHook]] = {}
        self._counter = 0

        if hooks:
            self.extend(hooks)

    @classmethod
    def from_input(
        cls,
        hooks: HookRegistry | HooksMapping | None,
        settings: HookSettings | None = None,
    ) -> HookRegistry:
        if isinstance(hooks, HookRegistry):
            if settings is None:
                return hooks

            cloned = hooks.clone()
            cloned.apply_settings(settings)
            return cloned

        return cls(hooks=hooks, settings=settings)

    def clone(self) -> HookRegistry:
        cloned = HookRegistry(
            settings={
                "default_mode": self.default_mode,
                "mode_by_event": cast(
                    dict[HookEvent, HookErrorMode], self.mode_by_event
                ),
            }
        )
        cloned._counter = self._counter
        cloned._hooks = {event: list(stored) for event, stored in self._hooks.items()}
        return cloned

    def apply_settings(self, settings: HookSettings) -> None:
        self.default_mode = settings.get("default_mode", self.default_mode)
        if mode_by_event := settings.get("mode_by_event"):
            for event, mode in mode_by_event.items():
                self.mode_by_event[event] = mode

    def extend(self, hooks: HooksMapping) -> None:
        for event, event_hooks in hooks.items():
            for hook in event_hooks:
                self.add(event, hook)

    def add(self, event: HookEvent | str, hook: HookInput) -> None:
        self._counter += 1
        self._hooks.setdefault(event, []).append(
            _StoredHook(registration=_to_registration(hook), order=self._counter)
        )

    def _iter_hooks(self, event: HookEvent | str) -> list[_StoredHook]:
        event_hooks = self._hooks.get(event, [])
        return sorted(
            event_hooks,
            key=lambda hook: (-hook.registration.priority, hook.order),
        )

    def _resolve_mode(
        self,
        event: HookEvent | str,
        registration: HookRegistration,
    ) -> HookErrorMode:
        if registration.mode is not None:
            return registration.mode

        return self.mode_by_event.get(event, self.default_mode)

    async def run(self, event: HookEvent | str, **kwargs: Any) -> None:
        event_hooks = self._iter_hooks(event)

        if not event_hooks:
            return

        # Hook payloads are read-only by default to avoid side effects.
        frozen_kwargs = {name: _freeze_payload(value) for name, value in kwargs.items()}

        for hook in event_hooks:
            registration = hook.registration
            try:
                result = registration.callback(**frozen_kwargs)
                if isawaitable(result):
                    if registration.timeout_seconds is None:
                        await result
                    else:
                        await asyncio.wait_for(
                            result,
                            timeout=registration.timeout_seconds,
                        )
            except Exception as e:
                mode = self._resolve_mode(event, registration)

                if mode == "robust":
                    logger.warning(
                        "Ignoring hook failure",
                        extra={
                            "event": event,
                            "hook_name": registration.label,
                            "hook_source": registration.origin,
                        },
                        exc_info=e,
                    )
                    continue

                raise
