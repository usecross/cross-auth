from __future__ import annotations

import logging
from typing import Any, ClassVar

from cross_web import AsyncHTTPRequest

from .._completion import AuthCompletion, AuthFlowState
from .._context import Context
from .._provider_service import (
    build_proxy_redirect_uri,
    exchange_and_attach_social_account,
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
    """Cookie-session social auth for first-party apps.

    One entry endpoint — ``GET /{provider}/login?next=`` — whose behavior
    branches on whether the user is already authenticated when the flow
    starts:

    - **Not authenticated**: the classic "Sign in with GitHub" flow. The
      library finds the user by email (auto-link policies apply) or creates
      a new one, then creates a session cookie and redirects to ``next``.
    - **Already authenticated**: treated as an attach. The provider account
      is linked to the current session user via
      ``exchange_and_attach_social_account`` (which enforces
      ``account_linking.enabled`` and email policies). The session is
      unchanged; user is redirected to ``next``.

    The merged behavior matches UX intuition: "Continue with GitHub" should
    log you in if you're logged out, and attach if you're already in.
    """

    kind: ClassVar[str] = "session"
    entry_methods: ClassVar[list[str]] = ["GET"]

    def entry_path(self, provider_id: str) -> str:
        return f"/{provider_id}/login"

    def __init__(
        self,
        *,
        session_config: SessionConfig | None = None,
        login_url: str = "/",
        default_post_login_redirect_url: str | None = None,
        attach_is_login_method: bool = True,
    ):
        self._session_config = session_config
        self._login_url = login_url
        self._default_post_login_redirect_url = default_post_login_redirect_url
        self._attach_is_login_method = attach_is_login_method

    async def start(
        self,
        request: AsyncHTTPRequest,
        context: Context,
        provider: OAuth2Provider,
    ) -> Response:
        next_url = self._validate_next(request.query_params.get("next"), context)
        user = context.get_user_from_request(request)

        completion_state: dict[str, Any] = {"next_url": next_url}
        if user is not None:
            completion_state["user_id"] = str(user.id)

        _, query_params = prepare_authorization(
            provider,
            request,
            context,
            kind=self.kind,
            completion_state=completion_state,
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
        expected_user_id = cs.get("user_id")
        proxy_redirect_uri = build_proxy_redirect_uri(request, context.base_url)
        next_url = (
            cs.get("next_url")
            or self._default_post_login_redirect_url
            or self._login_url
        )

        if expected_user_id is not None:
            # Attach path: user was authenticated at start, link this provider
            # account to them. Preserve existing session.
            current_user = context.get_user_from_request(request)
            if current_user is None or str(current_user.id) != expected_user_id:
                raise OAuth2Exception(
                    error="unauthorized",
                    error_description="Session changed during flow",
                )

            exchange_and_attach_social_account(
                current_user,
                provider,
                context,
                provider_code=callback_code,
                provider_code_verifier=flow_state.provider_code_verifier,
                proxy_redirect_uri=proxy_redirect_uri,
                callback_extra=callback_extra,
                is_login_method=self._attach_is_login_method,
            )
            return Response.redirect(next_url)

        # Login path: resolve/create user, make session cookie.
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
