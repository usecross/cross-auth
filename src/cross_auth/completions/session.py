from __future__ import annotations

import logging
from typing import Any, ClassVar

from cross_web import AsyncHTTPRequest

from .._completion import AuthCompletion, AuthFlowState
from .._context import Context
from .._provider_service import (
    build_proxy_redirect_uri,
    exchange_and_resolve_user,
    prepare_authorization,
)
from .._session import (
    SessionConfig,
    create_session,
    make_session_cookie,
    resolve_config,
)
from ..social_providers.oauth import OAuth2Exception, OAuth2Provider
from ..utils._response import Response

logger = logging.getLogger(__name__)


class SessionCompletion(AuthCompletion):
    """First-party social login: create a browser session after the provider round-trip.

    The user clicks a link to /{provider}/login?next=/profile on your own site,
    gets redirected to the provider, comes back, a session cookie is set, and
    they land at the validated `next` URL (or the configured default).

    Use this when the auth library and the app live in the same origin — the
    SPA/third-party path is AuthCodeCompletion.
    """

    kind: ClassVar[str] = "login"
    entry_methods: ClassVar[list[str]] = ["GET"]

    def __init__(
        self,
        *,
        session_config: SessionConfig | None = None,
        login_url: str = "/",
        default_post_login_redirect_url: str | None = None,
    ):
        self._session_config = session_config
        self._login_url = login_url
        self._default_post_login_redirect_url = default_post_login_redirect_url

    async def start(
        self,
        request: AsyncHTTPRequest,
        context: Context,
        provider: OAuth2Provider,
    ) -> Response:
        next_url = self._validate_next(request.query_params.get("next"), context)

        _, query_params = prepare_authorization(
            provider,
            request,
            context,
            kind=self.kind,
            completion_state={"next_url": next_url},
        )

        return Response.redirect(
            provider.authorization_endpoint,
            query_params=query_params,
        )

    async def complete(
        self,
        request: AsyncHTTPRequest,
        context: Context,
        provider: OAuth2Provider,
        callback_code: str,
        callback_extra: dict[str, Any] | None,
        flow_state: AuthFlowState,
    ) -> Response:
        proxy_redirect_uri = build_proxy_redirect_uri(request, context.base_url)

        result = exchange_and_resolve_user(
            provider,
            context,
            provider_code=callback_code,
            provider_code_verifier=flow_state.provider_code_verifier,
            proxy_redirect_uri=proxy_redirect_uri,
            callback_extra=callback_extra,
        )

        resolved = resolve_config(self._session_config)
        session_id, _ = create_session(
            str(result.user.id),
            context.secondary_storage,
            max_age=resolved["max_age"],
        )
        cookie = make_session_cookie(session_id, self._session_config)

        next_url = (
            flow_state.completion_state.get("next_url")
            or self._default_post_login_redirect_url
            or self._login_url
        )

        return Response.redirect(next_url, cookies=[cookie])

    async def on_failure(
        self,
        request: AsyncHTTPRequest,
        context: Context,
        error: OAuth2Exception,
        flow_state: AuthFlowState,
    ) -> Response:
        return Response.redirect(
            self._login_url,
            query_params={"error": error.error},
        )

    def _validate_next(self, raw: str | None, context: Context) -> str | None:
        """Return a safe next-URL or None if unsafe/missing."""
        if not raw:
            return None
        if raw.startswith("/") and not raw.startswith("//"):
            return raw
        if context.is_valid_redirect_uri(raw):
            return raw
        logger.warning("Ignoring untrusted next URL: %s", raw)
        return None
