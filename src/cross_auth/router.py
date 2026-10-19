import logging
import warnings
from collections.abc import Callable
from functools import partial
from typing import Any, Self

from cross_web import HTTPRequest, Response
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
from ._clients import ClientResolver
from ._config import Config
from ._context import AccountsStorage, Context, SecondaryStorage, User
from ._issuer import Issuer
from ._route import Route
from ._setup import AuthSetup, build_auth_setup
from ._storage import SessionStorage
from ._tokens import TokenIssuer
from .hooks import HookRegistry
from .social_providers.oauth import OAuth2Provider

logger = logging.getLogger(__name__)

_TRUSTED_ORIGINS_DEPRECATION = (
    "trusted_origins has no effect and will be removed in a future release. "
    "It does not configure CORS or CSRF protection; configure those in your "
    "application."
)


FlowHandler = Callable[..., Response]


def _provider_routes(provider: OAuth2Provider, *, cookie_auth: bool) -> list[Route]:
    prefix = f"/{provider.id}"

    def bound(
        handler: FlowHandler,
    ) -> Callable[..., Response]:
        return partial(handler, provider)

    routes: list[Route] = []

    if cookie_auth:
        routes.append(
            Route(
                path=f"{prefix}/login",
                methods=["GET"],
                function=bound(start_session_flow),
                operation_id=f"{provider.id}_login",
            )
        )

    routes.extend(
        [
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
                path_parameters=[
                    {
                        "name": "social_account_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string", "title": "Social Account Id"},
                    }
                ],
            ),
            Route(
                path=f"{prefix}/authorize",
                methods=["GET"],
                function=bound(start_token_flow),
                operation_id=f"{provider.id}_authorize",
            ),
            Route(
                path=f"{prefix}/callback",
                methods=["GET"],
                function=bound(handle_callback),
                operation_id=f"{provider.id}_callback",
            ),
            Route(
                path=f"{prefix}/callback",
                methods=["POST"],  # POST for Apple (response_mode=form_post)
                function=bound(handle_callback),
                operation_id=f"{provider.id}_callback_post",
                read_form_data=True,
            ),
            Route(
                path=f"{prefix}/link",
                methods=["POST"],
                function=bound(start_link_flow),
                operation_id=f"{provider.id}_link",
                read_body=True,
            ),
            Route(
                path=f"{prefix}/finalize-link",
                methods=["POST"],
                function=bound(finalize_link),
                operation_id=f"{provider.id}_finalize_link",
                read_body=True,
            ),
        ]
    )

    return routes


class AuthRouter(APIRouter):
    context: Context
    issuer: Issuer
    extra_schemas: dict[str, Any]

    def __init__(
        self,
        providers: list[OAuth2Provider],
        secondary_storage: SecondaryStorage,
        accounts_storage: AccountsStorage,
        get_user_from_request: Callable[[HTTPRequest], User | None],
        trusted_origins: list[str] | None = None,
        session_storage: SessionStorage | None = None,
        token_issuer: TokenIssuer | None = None,
        base_url: str | None = None,
        config: Config | None = None,
        default_next_url: str = "/",
        hooks: HookRegistry | None = None,
        normalize_email: Callable[[str], str] | None = None,
        get_client: ClientResolver | None = None,
    ):
        if trusted_origins is not None:
            warnings.warn(
                _TRUSTED_ORIGINS_DEPRECATION, DeprecationWarning, stacklevel=2
            )
        setup = build_auth_setup(
            providers=providers,
            secondary_storage=secondary_storage,
            accounts_storage=accounts_storage,
            session_storage=session_storage,
            token_issuer=token_issuer,
            get_user_from_request=get_user_from_request,
            base_url=base_url,
            config=config,
            default_next_url=default_next_url,
            hooks=hooks,
            normalize_email=normalize_email,
            get_client=get_client,
        )
        self._mount(setup)

    @classmethod
    def _from_setup(cls, setup: AuthSetup) -> Self:
        """Route against a setup that was already built (by ``CrossAuth``)."""
        router = cls.__new__(cls)
        router._mount(setup)
        return router

    def _mount(self, setup: AuthSetup) -> None:
        super().__init__()

        self.issuer = setup.issuer
        self.extra_schemas = {}
        self.context = setup.context

        provider_routes: list[Route] = []
        for provider in setup.providers:
            provider_routes.extend(
                _provider_routes(
                    provider, cookie_auth=setup.context.cookie_auth_enabled
                )
            )

        for route in provider_routes + self.issuer.routes:
            self.add_api_route(
                route.path,
                route.to_fastapi_endpoint(setup.context),
                methods=route.methods,
                response_model=route.response_model,
                operation_id=route.operation_id,
                openapi_extra=route.get_openapi_extra(),
                summary=route.summary,
            )

            if route.openapi_schemas:
                self.extra_schemas.update(route.openapi_schemas)
