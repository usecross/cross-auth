import logging
from collections.abc import Callable
from itertools import chain
from typing import Any

from fastapi import APIRouter, Request
from cross_web import AsyncHTTPRequest

from ._auth import AuthManager
from ._config import Config, SessionConfig
from ._context import AccountsStorage, Context, SecondaryStorage, User
from ._issuer import Issuer
from ._session import SessionManager
from ._storage import SessionStorage
from .social_providers.oauth import OAuth2Provider

logger = logging.getLogger(__name__)


class AuthRouter(APIRouter):
    extra_schemas: dict[str, Any]
    _context: Context

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
        # Session-based auth (optional)
        session_storage: SessionStorage | None = None,
        session_config: SessionConfig | None = None,
        # Email/password auth options
        enable_signup: bool = True,
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
        self._session_storage = session_storage
        self._session_config = session_config

        # Create managers
        self.session_manager = (
            SessionManager(session_config) if session_storage else None
        )
        self.auth_manager = AuthManager(enable_signup=enable_signup)

        provider_routes = list(chain.from_iterable(p.routes for p in providers))

        # Collect all routes
        routes = provider_routes + self.issuer.routes + self.auth_manager.routes
        if self.session_manager:
            routes += self.session_manager.routes

        # Create context (store for helper methods)
        self._context = Context(
            secondary_storage=self._secondary_storage,
            accounts_storage=self._accounts_storage,
            create_token=self._create_token,
            trusted_origins=self._trusted_origins,
            get_user_from_request=self._get_user_from_request,
            base_url=self._base_url,
            config=self._config,
            session_storage=self._session_storage,
            session_config=self._session_config,
        )

        for route in routes:
            self.add_api_route(
                route.path,
                route.to_fastapi_endpoint(self._context),
                methods=route.methods,
                response_model=route.response_model,
                operation_id=route.operation_id,
                openapi_extra=route.openapi,
                summary=route.summary,
            )

            if route.openapi_schemas:
                self.extra_schemas.update(route.openapi_schemas)

    def get_authenticated_user(self, request: Request) -> User | None:
        """Helper method for middleware integration (e.g., Inertia share function).

        Extracts session cookie (if sessions enabled), validates it, and returns
        the user or None. Falls back to token-based auth if no session.

        This is useful for sharing auth state to all pages in server-rendered apps.

        Example:
            async def share_auth(request: Request) -> dict:
                user = auth_router.get_authenticated_user(request)
                return {
                    "auth": {
                        "user": {"id": user.id, "email": user.email} if user else None,
                        "authenticated": user is not None,
                    }
                }

            app.add_middleware(InertiaMiddleware, share=share_auth)
        """
        # Convert FastAPI request to cross_web request for session extraction
        async_request = AsyncHTTPRequest.from_fastapi(request)

        # Try session-based auth first
        if self._context.session_enabled:
            session = self._context.get_session_from_request(async_request)
            if session:
                return self._context.accounts_storage.find_user_by_id(session.user_id)

        # Fall back to token-based auth
        return self._context.get_user_from_request(async_request)
