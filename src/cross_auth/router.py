import logging
from collections.abc import Callable
from itertools import chain
from typing import Any

from fastapi import APIRouter
from cross_web import AsyncHTTPRequest

from ._config import Config
from ._context import AccountsStorage, Context, SecondaryStorage, User
from ._issuer import Issuer
from .social_providers.oauth import OAuth2Provider

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

        provider_routes = list(chain.from_iterable(p.routes for p in providers))

        routes = provider_routes + self.issuer.routes

        # TODO: maybe this should be a dependency (or at least instantiated in the endpoint code)
        context = Context(
            secondary_storage=self._secondary_storage,
            accounts_storage=self._accounts_storage,
            create_token=self._create_token,
            trusted_origins=self._trusted_origins,
            get_user_from_request=self._get_user_from_request,
            base_url=self._base_url,
            config=self._config,
        )

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
