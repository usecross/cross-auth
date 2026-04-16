from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, ClassVar

from cross_web import AsyncHTTPRequest
from pydantic import BaseModel, Field

from ._context import Context
from ._route import Route
from ._storage import SocialAccount, User
from .models.oauth_token_response import TokenResponse
from .social_providers.oauth import (
    OAuth2Exception,
    OAuth2Provider,
    UserInfo,
    ValidatedUserInfo,
)
from .utils._response import Response


class AuthFlowState(BaseModel):
    """State persisted between a flow's entry endpoint and the provider callback.

    Generic across completions. Completion-specific fields live in
    `completion_state`, which is opaque to the router and handed back to the
    owning AuthCompletion unchanged when the provider callback returns.
    """

    kind: str
    provider_id: str
    state: str
    provider_code_verifier: str | None = None
    completion_state: dict[str, Any] = Field(default_factory=dict)


@dataclass
class ProviderAuthResult:
    """The local user and social account resolved from a provider round-trip.

    Produced by _provider_service.exchange_and_resolve_user. Completions that
    defer provider token exchange (e.g. LinkCompletion) do not produce this.
    """

    user: User
    social_account: SocialAccount
    is_new_user: bool
    provider_tokens: TokenResponse
    user_info: UserInfo
    validated: ValidatedUserInfo


class AuthCompletion(ABC):
    """A strategy for completing an OAuth flow after the provider round-trip.

    Completions name themselves via `kind`. The router persists `kind` in the
    flow state and dispatches to the matching completion when the provider
    callback returns.

    Each completion owns:
    - the entry endpoint clients use to start its flow (one per provider)
    - what to validate and persist before redirecting to the provider
    - the final response shape (cookie+redirect, code+redirect, link code, etc.)
    - failure rendering after the provider round-trip
    - any auxiliary routes it needs (e.g. /{provider}/finalize-link)
    """

    kind: ClassVar[str]
    entry_methods: ClassVar[list[str]] = ["GET"]

    def entry_path(self, provider_id: str) -> str:
        """Path for this completion's entry endpoint for a given provider.

        Defaults to /{provider_id}/{kind}. Override to reshape.
        """
        return f"/{provider_id}/{self.kind}"

    @abstractmethod
    async def start(
        self,
        request: AsyncHTTPRequest,
        context: Context,
        provider: OAuth2Provider,
    ) -> Response:
        """Handle the entry endpoint: validate, persist state, redirect to provider.

        Completions call `prepare_authorization` to generate + persist state and
        build the provider redirect URL. On validation failure, return an error
        Response directly (shape is mode-specific: JSON error, login redirect,
        client redirect with OAuth error params, etc.).
        """

    @abstractmethod
    async def complete(
        self,
        request: AsyncHTTPRequest,
        context: Context,
        provider: OAuth2Provider,
        callback_code: str,
        callback_extra: dict[str, Any] | None,
        flow_state: AuthFlowState,
    ) -> Response:
        """Produce the final response after a verified provider callback.

        May raise OAuth2Exception; the router will call on_failure() with
        the loaded flow_state so the completion can render appropriately.
        """

    @abstractmethod
    async def on_failure(
        self,
        request: AsyncHTTPRequest,
        context: Context,
        error: OAuth2Exception,
        flow_state: AuthFlowState,
    ) -> Response:
        """Render a post-callback failure.

        Only called after flow_state has been successfully loaded — pre-load
        callback errors (unknown state, expired state) are rendered directly
        by the router as generic JSON errors because no completion can be
        identified.
        """

    def extra_routes(self, providers: dict[str, OAuth2Provider]) -> list[Route]:
        """Auxiliary routes owned by this completion.

        Called once at router construction. Completions that need per-provider
        auxiliary routes (e.g. LinkCompletion's /finalize-link) iterate the
        provider registry and emit one route per provider.
        """
        return []
