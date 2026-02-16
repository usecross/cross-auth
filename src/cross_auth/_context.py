from __future__ import annotations

from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

from cross_web import AsyncHTTPRequest

from ._config import Config
from ._hooks import HookEvent, HookRegistry, HookSettings, HooksMapping
from ._storage import AccountsStorage, SecondaryStorage, User
from .utils._is_same_host import is_same_host


class Context:
    def __init__(
        self,
        secondary_storage: SecondaryStorage,
        accounts_storage: AccountsStorage,
        create_token: Callable[[str], tuple[str, int]],
        # TODO: this doesn't allow to use the library as an Identity Provider
        trusted_origins: list[str],
        get_user_from_request: Callable[[AsyncHTTPRequest], User | None],
        base_url: str | None = None,
        config: Config | None = None,
        hooks: HookRegistry | HooksMapping | None = None,
        hook_settings: HookSettings | None = None,
    ):
        self.secondary_storage = secondary_storage
        self.accounts_storage = accounts_storage
        self.create_token = create_token
        self.trusted_origins = trusted_origins
        self.get_user_from_request = get_user_from_request
        self.base_url = base_url
        self.config: Config = config or {}
        self._hook_settings = hook_settings
        self._hooks = HookRegistry.from_input(hooks, settings=hook_settings)

    @property
    def hooks(self) -> HookRegistry:
        return self._hooks

    @hooks.setter
    def hooks(self, hooks: HookRegistry | HooksMapping | None) -> None:
        self._hooks = HookRegistry.from_input(hooks, settings=self._hook_settings)

    async def run_hooks(self, event: HookEvent | str, **kwargs: Any) -> None:
        await self._hooks.run(event, **kwargs)

    def is_valid_redirect_uri(self, redirect_uri: str) -> bool:
        host = urlparse(redirect_uri).netloc

        for origin in self.trusted_origins:
            if is_same_host(host, origin):
                return True

        return False

    def is_valid_client_id(self, client_id: str) -> bool:
        """Validate client_id against allowed_client_ids config.

        If allowed_client_ids is not configured or empty, any client_id is accepted.
        """
        allowed = self.config.get("allowed_client_ids")

        if not allowed:
            return True

        return client_id in allowed
