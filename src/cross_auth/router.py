import logging
from collections.abc import Awaitable, Callable
from functools import partial
from typing import Any

from cross_web import AsyncHTTPRequest, Cookie, Response
from fastapi import APIRouter

from ._auth_flow import (
    finalize_link,
    handle_callback,
    start_link_flow,
    start_session_flow,
    start_token_flow,
)
from ._config import Config
from ._context import AccountsStorage, Context, SecondaryStorage, User
from ._issuer import Issuer
from ._route import Route
from .social_providers.oauth import OAuth2Provider

logger = logging.getLogger(__name__)


FlowHandler = Callable[[OAuth2Provider, AsyncHTTPRequest, Context], Awaitable[Response]]


def _provider_routes(provider: OAuth2Provider) -> list[Route]:
    """Build the 5 HTTP routes that expose a provider's auth flows."""
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
        create_session_cookie: Callable[[str], Cookie] | None = None,
        default_next_url: str = "/",
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
            create_session_cookie=create_session_cookie,
            default_next_url=default_next_url,
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
