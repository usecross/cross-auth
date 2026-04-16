from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Any

from cross_web import AsyncHTTPRequest
from fastapi import APIRouter

from ._completion import AuthCompletion
from ._config import Config
from ._context import AccountsStorage, Context, SecondaryStorage, User
from ._issuer import Issuer
from ._provider_service import parse_callback_and_load_state
from ._route import Route
from .social_providers.oauth import OAuth2Exception, OAuth2Provider
from .utils._response import Response

logger = logging.getLogger(__name__)


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
        completions: list[AuthCompletion] | None = None,
        base_url: str | None = None,
        config: Config | None = None,
    ):
        super().__init__()

        self.issuer = Issuer()
        self.extra_schemas = {}

        self._secondary_storage = secondary_storage
        self._accounts_storage = accounts_storage
        self._create_token = create_token
        self._trusted_origins = trusted_origins
        self._get_user_from_request = get_user_from_request
        self._base_url = base_url
        self._config = config
        self._completions = completions or []
        self._providers = {p.id: p for p in providers}

        context = Context(
            secondary_storage=secondary_storage,
            accounts_storage=accounts_storage,
            create_token=create_token,
            trusted_origins=trusted_origins,
            get_user_from_request=get_user_from_request,
            base_url=base_url,
            config=config,
        )

        completion_map = {c.kind: c for c in self._completions}
        routes = self._build_routes(providers, completion_map)

        for route in routes:
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

    def _build_routes(
        self,
        providers: list[OAuth2Provider],
        completion_map: dict[str, AuthCompletion],
    ) -> list[Route]:
        routes: list[Route] = []

        for completion in self._completions:
            for provider in providers:
                routes.append(
                    Route(
                        path=completion.entry_path(provider.id),
                        methods=completion.entry_methods,
                        function=_make_start_handler(completion, provider),
                        operation_id=f"{provider.id}_{completion.kind}_start",
                    )
                )

        for provider in providers:
            routes.append(
                Route(
                    path=f"/{provider.id}/callback",
                    methods=["GET", "POST"],
                    function=_make_callback_handler(provider, completion_map),
                    operation_id=f"{provider.id}_callback",
                )
            )

        for completion in self._completions:
            routes.extend(completion.extra_routes(self._providers))

        routes.extend(self.issuer.routes)

        return routes


def _make_start_handler(
    completion: AuthCompletion, provider: OAuth2Provider
) -> Callable[[AsyncHTTPRequest, Context], Awaitable[Response]]:
    async def handler(request: AsyncHTTPRequest, context: Context) -> Response:
        return await completion.start(request, context, provider)

    return handler


def _make_callback_handler(
    provider: OAuth2Provider,
    completion_map: dict[str, AuthCompletion],
) -> Callable[[AsyncHTTPRequest, Context], Awaitable[Response]]:
    async def handler(request: AsyncHTTPRequest, context: Context) -> Response:
        try:
            callback_data, flow_state = await parse_callback_and_load_state(
                provider, request, context
            )
        except OAuth2Exception as e:
            return Response.error(e.error, error_description=e.error_description)

        if flow_state.provider_id != provider.id:
            logger.error(
                "Flow state provider mismatch: state=%s, endpoint=%s",
                flow_state.provider_id,
                provider.id,
            )
            return Response.error(
                "server_error",
                error_description="Flow state provider mismatch",
            )

        completion = completion_map.get(flow_state.kind)
        if completion is None:
            logger.error("No completion registered for kind=%s", flow_state.kind)
            return Response.error(
                "server_error",
                error_description=f"No completion registered for kind={flow_state.kind}",
            )

        if not callback_data.code:
            error = OAuth2Exception(
                error="server_error",
                error_description="No authorization code received in callback",
            )
            return await completion.on_failure(request, context, error, flow_state)

        try:
            return await completion.complete(
                request,
                context,
                provider,
                callback_data.code,
                callback_data.extra,
                flow_state,
            )
        except OAuth2Exception as e:
            return await completion.on_failure(request, context, e, flow_state)

    return handler
