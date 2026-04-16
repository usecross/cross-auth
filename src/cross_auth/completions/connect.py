from __future__ import annotations

import logging
from typing import Any, ClassVar

from cross_web import AsyncHTTPRequest

from .._completion import AuthCompletion, AuthFlowState
from .._context import Context
from .._provider_service import (
    build_proxy_redirect_uri,
    exchange_and_attach_social_account,
    prepare_authorization,
)
from ..social_providers.oauth import OAuth2Exception, OAuth2Provider
from ..utils._response import Response

logger = logging.getLogger(__name__)


class ConnectCompletion(AuthCompletion):
    """First-party account linking: attach a provider to the current session user.

    The user is already logged in via a session cookie. They visit
    /{provider}/connect?next=/settings, the browser round-trips through the
    provider, and on return a SocialAccount is attached to their current user
    — then redirected to the `next` URL.

    This is the session-mode counterpart of LinkCompletion (which is
    SPA-mode: POST + PKCE + /finalize-link).
    """

    kind: ClassVar[str] = "connect"
    entry_methods: ClassVar[list[str]] = ["GET"]

    def __init__(
        self,
        *,
        login_url: str = "/",
        default_post_connect_redirect_url: str | None = None,
        is_login_method: bool = True,
    ):
        self._login_url = login_url
        self._default_post_connect_redirect_url = default_post_connect_redirect_url
        self._is_login_method = is_login_method

    async def start(
        self,
        request: AsyncHTTPRequest,
        context: Context,
        provider: OAuth2Provider,
    ) -> Response:
        user = context.get_user_from_request(request)
        if user is None:
            logger.info("Connect flow requires authenticated user")
            return Response.redirect(
                self._login_url,
                query_params={"error": "unauthorized"},
            )

        account_linking = context.config.get("account_linking", {})
        if not account_linking.get("enabled", False):
            return Response.redirect(
                self._login_url,
                query_params={"error": "linking_disabled"},
            )

        next_url = self._validate_next(request.query_params.get("next"), context)

        _, query_params = prepare_authorization(
            provider,
            request,
            context,
            kind=self.kind,
            completion_state={
                "next_url": next_url,
                "user_id": str(user.id),
            },
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
        cs = flow_state.completion_state
        expected_user_id = cs["user_id"]

        current_user = context.get_user_from_request(request)
        if current_user is None or str(current_user.id) != expected_user_id:
            raise OAuth2Exception(
                error="unauthorized",
                error_description="Session changed during connect flow",
            )

        proxy_redirect_uri = build_proxy_redirect_uri(request, context.base_url)

        exchange_and_attach_social_account(
            current_user,
            provider,
            context,
            provider_code=callback_code,
            provider_code_verifier=flow_state.provider_code_verifier,
            proxy_redirect_uri=proxy_redirect_uri,
            callback_extra=callback_extra,
            is_login_method=self._is_login_method,
        )

        next_url = (
            cs.get("next_url")
            or self._default_post_connect_redirect_url
            or self._login_url
        )

        return Response.redirect(next_url)

    async def on_failure(
        self,
        request: AsyncHTTPRequest,
        context: Context,
        error: OAuth2Exception,
        flow_state: AuthFlowState,
    ) -> Response:
        fallback = (
            flow_state.completion_state.get("next_url")
            or self._default_post_connect_redirect_url
            or self._login_url
        )
        return Response.redirect(
            fallback,
            query_params={"error": error.error},
        )

    def _validate_next(self, raw: str | None, context: Context) -> str | None:
        if not raw:
            return None
        if raw.startswith("/") and not raw.startswith("//"):
            return raw
        if context.is_valid_redirect_uri(raw):
            return raw
        logger.warning("Ignoring untrusted next URL: %s", raw)
        return None
