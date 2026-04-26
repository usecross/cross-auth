import logging
from collections.abc import Awaitable, Callable
from functools import partial
from typing import Any

from cross_web import AsyncHTTPRequest, Response
from fastapi import APIRouter

from ._auth_flow import (
    disconnect_provider,
    finalize_link,
    handle_callback,
    start_connect_flow,
    start_link_flow,
    start_session_flow,
    start_token_flow,
)
from ._config import Config
from ._context import AccountsStorage, Context, SecondaryStorage, User
from ._issuer import Issuer
from ._route import Route
from ._session import SessionConfig
from .hooks import HookRegistry
from .social_providers.oauth import OAuth2Provider

logger = logging.getLogger(__name__)


FlowHandler = Callable[[OAuth2Provider, AsyncHTTPRequest, Context], Awaitable[Response]]


def _provider_routes(provider: OAuth2Provider) -> list[Route]:
    prefix = f"/{provider.id}"

    def bound(
        handler: FlowHandler,
    ) -> Callable[[AsyncHTTPRequest, Context], Awaitable[Response]]:
        return partial(handler, provider)

    return [
        Route(
            path=f"{prefix}/login",
            methods=["GET"],
            function=bound(start_session_flow),
            operation_id=f"{provider.id}_login",
        ),
        Route(
            path=f"{prefix}/connect",
            methods=["GET"],
            function=bound(start_connect_flow),
            operation_id=f"{provider.id}_connect",
        ),
        Route(
            path=f"{prefix}/social-accounts",
            methods=["DELETE"],
            function=bound(disconnect_provider),
            operation_id=f"{provider.id}_disconnect",
        ),
        Route(
            path=f"{prefix}/social-accounts/{{social_account_id}}",
            methods=["DELETE"],
            function=bound(disconnect_provider),
            operation_id=f"{provider.id}_disconnect_account",
        ),
        Route(
            path=f"{prefix}/authorize",
            methods=["GET"],
            function=bound(start_token_flow),
            operation_id=f"{provider.id}_authorize",
        ),
        Route(
            path=f"{prefix}/callback",
            methods=["GET", "POST"],  # POST for Apple (response_mode=form_post)
            function=bound(handle_callback),
            operation_id=f"{provider.id}_callback",
        ),
        Route(
            path=f"{prefix}/link",
            methods=["POST"],
            function=bound(start_link_flow),
            operation_id=f"{provider.id}_link",
        ),
        Route(
            path=f"{prefix}/finalize-link",
            methods=["POST"],
            function=bound(finalize_link),
            operation_id=f"{provider.id}_finalize_link",
        ),
    ]


class AuthRouter(APIRouter):
    extra_schemas: dict[str, Any]

    def __init__(
        self,
        providers: list[OAuth2Provider],
        secondary_storage: SecondaryStorage,
        accounts_storage: AccountsStorage,
        get_user_from_request: Callable[[AsyncHTTPRequest], User | None],
        create_token: Callable[[str], tuple[str, int]],
        trusted_origins: list[str],
        base_url: str | None = None,
        config: Config | None = None,
        session_enabled: bool = False,
        session_config: SessionConfig | None = None,
        default_next_url: str = "/",
        hooks: HookRegistry | None = None,
    ):
        super().__init__()

        self.issuer = Issuer()
        self.extra_schemas = {}

        context = Context(
            secondary_storage=secondary_storage,
            accounts_storage=accounts_storage,
            create_token=create_token,
            trusted_origins=trusted_origins,
            get_user_from_request=get_user_from_request,
            base_url=base_url,
            config=config,
            session_enabled=session_enabled,
            session_config=session_config,
            default_next_url=default_next_url,
            hooks=hooks,
        )

        provider_routes: list[Route] = []
        for provider in providers:
            provider_routes.extend(_provider_routes(provider))

        for route in provider_routes + self.issuer.routes:
            self.add_api_route(
                route.path,
                route.to_fastapi_endpoint(context),
                methods=route.methods,
                response_model=route.response_model,
                operation_id=route.operation_id,
                openapi_extra=route.openapi,
                summary=route.summary,
            )

            if route.openapi_schemas:
                self.extra_schemas.update(route.openapi_schemas)
