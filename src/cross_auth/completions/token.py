from __future__ import annotations

import json
import logging
import uuid
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta, timezone
from typing import Any, ClassVar
from urllib.parse import urlencode

from cross_web import AsyncHTTPRequest
from pydantic import HttpUrl, TypeAdapter, ValidationError

from .._completion import AuthCompletion, AuthFlowState
from .._context import Context
from .._issuer import AuthorizationCodeGrantData
from .._provider_service import (
    build_proxy_redirect_uri,
    exchange_and_attach_social_account,
    exchange_and_resolve_user,
    prepare_authorization,
)
from .._route import Route
from ..social_providers.oauth import (
    InitiateLinkRequest,
    InitiateLinkResponse,
    OAuth2Exception,
    OAuth2LinkCodeData,
    OAuth2Provider,
)
from ..utils._pkce import validate_pkce
from ..utils._response import Response

logger = logging.getLogger(__name__)

# Discriminator in flow_state.completion_state — set by start() or by the
# POST /link handler so complete() knows which sub-flow's callback this is.
_SUB_AUTH_CODE = "auth_code"
_SUB_LINK = "link"


class TokenCompletion(AuthCompletion):
    """OAuth 2.0 code flow + account linking for token-based clients (SPAs, mobile).

    Contributes three endpoints per provider:

    - ``GET /{provider}/authorize`` — standard OAuth 2.0 auth-code entry with
      PKCE + ``client_id`` + ``redirect_uri``. On callback, exchanges the
      provider code, resolves/creates the local user, issues a local code,
      and redirects back to the client's ``redirect_uri``. The client
      exchanges the local code at ``POST /token`` (served by the Issuer).
    - ``POST /{provider}/link`` — authenticated JSON endpoint that initiates
      an account-link flow. Returns a JSON body with an ``authorization_url``
      for the SPA to redirect to. On callback, the provider code is stored
      under a fresh ``link_code`` and the SPA is sent back with
      ``?link_code=…``.
    - ``POST /{provider}/finalize-link`` — the SPA confirms the link by
      sending the ``link_code`` + its PKCE ``code_verifier``. The library
      exchanges the provider code and attaches the SocialAccount.

    All three share the same ``/{provider}/callback`` with dispatch on a
    ``sub_flow`` field in ``completion_state``.
    """

    kind: ClassVar[str] = "token"
    entry_methods: ClassVar[list[str]] = ["GET"]

    def entry_path(self, provider_id: str) -> str:
        return f"/{provider_id}/authorize"

    async def start(
        self,
        request: AsyncHTTPRequest,
        context: Context,
        provider: OAuth2Provider,
    ) -> Response:
        """OAuth 2.0 auth-code entry (GET /{provider}/authorize)."""
        redirect_uri = request.query_params.get("redirect_uri")
        if not redirect_uri:
            logger.error("No redirect URI provided")
            return Response.error("invalid_request")

        try:
            redirect_uri = str(TypeAdapter(HttpUrl).validate_python(redirect_uri))
        except ValidationError:
            logger.error("Invalid redirect URI")
            return Response.error("invalid_redirect_uri")

        if not context.is_valid_redirect_uri(redirect_uri):
            logger.error("Invalid redirect URI")
            return Response.error("invalid_redirect_uri")

        client_state = request.query_params.get("state")

        response_type = request.query_params.get("response_type")
        if not response_type:
            return Response.error_redirect(
                redirect_uri,
                error="invalid_request",
                error_description="No response type provided",
                state=client_state,
            )
        if response_type != "code":
            return Response.error_redirect(
                redirect_uri,
                error="invalid_request",
                error_description="Unsupported response type",
                state=client_state,
            )

        code_challenge = request.query_params.get("code_challenge")
        code_challenge_method = request.query_params.get("code_challenge_method")
        if not code_challenge:
            return Response.error_redirect(
                redirect_uri,
                error="invalid_request",
                error_description="No code challenge provided",
                state=client_state,
            )
        if code_challenge_method != "S256":
            return Response.error_redirect(
                redirect_uri,
                error="invalid_request",
                error_description="Unsupported code challenge method",
                state=client_state,
            )

        client_id = request.query_params.get("client_id")
        if not client_id:
            return Response.error_redirect(
                redirect_uri,
                error="invalid_request",
                error_description="No client_id provided",
                state=client_state,
            )
        if not context.is_valid_client_id(client_id):
            return Response.error_redirect(
                redirect_uri,
                error="invalid_client",
                error_description="Invalid client_id",
                state=client_state,
            )

        login_hint = request.query_params.get("login_hint")

        _, query_params = prepare_authorization(
            provider,
            request,
            context,
            kind=self.kind,
            completion_state={
                "sub_flow": _SUB_AUTH_CODE,
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "code_challenge": code_challenge,
                "code_challenge_method": code_challenge_method,
                "client_state": client_state,
                "login_hint": login_hint,
            },
            login_hint=login_hint,
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
        sub_flow = flow_state.completion_state.get("sub_flow", _SUB_AUTH_CODE)
        if sub_flow == _SUB_LINK:
            return await self._complete_link(
                request, context, callback_code, callback_extra, flow_state
            )
        return await self._complete_auth_code(
            request, context, provider, callback_code, callback_extra, flow_state
        )

    async def _complete_auth_code(
        self,
        request: AsyncHTTPRequest,
        context: Context,
        provider: OAuth2Provider,
        callback_code: str,
        callback_extra: dict[str, Any] | None,
        flow_state: AuthFlowState,
    ) -> Response:
        cs = flow_state.completion_state
        redirect_uri = cs["redirect_uri"]
        client_state = cs.get("client_state")

        proxy_redirect_uri = build_proxy_redirect_uri(request, context.base_url)
        result = exchange_and_resolve_user(
            provider,
            context,
            provider_code=callback_code,
            provider_code_verifier=flow_state.provider_code_verifier,
            proxy_redirect_uri=proxy_redirect_uri,
            callback_extra=callback_extra,
        )

        code = str(uuid.uuid4())
        grant = AuthorizationCodeGrantData(
            user_id=str(result.user.id),
            expires_at=datetime.now(tz=timezone.utc) + timedelta(minutes=10),
            client_id=cs["client_id"],
            redirect_uri=redirect_uri,
            code_challenge=cs["code_challenge"],
            code_challenge_method=cs["code_challenge_method"],
        )
        context.secondary_storage.set(
            f"oauth:code:{code}",
            grant.model_dump_json(),
        )

        query_params: dict[str, str] = {"code": code}
        if client_state:
            query_params["state"] = client_state
        return Response.redirect(redirect_uri, query_params=query_params)

    async def _complete_link(
        self,
        request: AsyncHTTPRequest,
        context: Context,
        callback_code: str,
        callback_extra: dict[str, Any] | None,
        flow_state: AuthFlowState,
    ) -> Response:
        # Link flow DEFERS provider token exchange to /finalize-link.
        # Store the provider code with metadata; the client will finalize.
        cs = flow_state.completion_state
        link_code = str(uuid.uuid4())

        data = OAuth2LinkCodeData(
            expires_at=datetime.now(tz=timezone.utc) + timedelta(minutes=10),
            client_id=cs["client_id"],
            redirect_uri=cs["redirect_uri"],
            code_challenge=cs["code_challenge"],
            code_challenge_method=cs["code_challenge_method"],
            user_id=cs["user_id"],
            provider_code=callback_code,
            provider_code_verifier=flow_state.provider_code_verifier,
            client_state=cs.get("client_state"),
            provider_callback_extra=callback_extra,
        )
        context.secondary_storage.set(
            f"oauth:link_request:{link_code}",
            data.model_dump_json(),
        )
        return Response.redirect(
            cs["redirect_uri"],
            query_params={"link_code": link_code},
        )

    async def on_failure(
        self,
        request: AsyncHTTPRequest,
        context: Context,
        error: OAuth2Exception,
        flow_state: AuthFlowState,
    ) -> Response:
        cs = flow_state.completion_state
        redirect_uri = cs.get("redirect_uri")
        if not redirect_uri:
            return Response.error(
                error.error,
                error_description=error.error_description,
            )
        return Response.error_redirect(
            redirect_uri,
            error=error.error,
            error_description=error.error_description,
            state=cs.get("client_state"),
        )

    def extra_routes(self, providers: dict[str, OAuth2Provider]) -> list[Route]:
        routes: list[Route] = []
        for provider_id, provider in providers.items():
            routes.append(
                Route(
                    path=f"/{provider_id}/link",
                    methods=["POST"],
                    function=self._make_link_start_handler(provider),
                    operation_id=f"{provider_id}_link_start",
                )
            )
            routes.append(
                Route(
                    path=f"/{provider_id}/finalize-link",
                    methods=["POST"],
                    function=self._make_finalize_handler(provider),
                    operation_id=f"{provider_id}_finalize_link",
                )
            )
        return routes

    def _make_link_start_handler(
        self, provider: OAuth2Provider
    ) -> Callable[[AsyncHTTPRequest, Context], Awaitable[Response]]:
        async def handler(request: AsyncHTTPRequest, context: Context) -> Response:
            return await self._link_start(request, context, provider)

        return handler

    def _make_finalize_handler(
        self, provider: OAuth2Provider
    ) -> Callable[[AsyncHTTPRequest, Context], Awaitable[Response]]:
        async def handler(request: AsyncHTTPRequest, context: Context) -> Response:
            return await self._finalize_link(request, context, provider)

        return handler

    async def _link_start(
        self,
        request: AsyncHTTPRequest,
        context: Context,
        provider: OAuth2Provider,
    ) -> Response:
        """POST /{provider}/link — SPA-initiated account link start.

        Returns JSON with the provider authorization URL; the SPA performs
        the redirect itself. Flow state is tagged ``sub_flow=link`` so the
        shared callback dispatcher routes to the link branch.
        """
        user = context.get_user_from_request(request)
        if user is None:
            logger.error("User must be authenticated to initiate link flow")
            return Response.error(
                "unauthorized",
                error_description="User must be authenticated to initiate link flow",
                status_code=401,
            )

        account_linking = context.config.get("account_linking", {})
        if not account_linking.get("enabled", False):
            logger.error("Account linking is not enabled")
            return Response.error(
                "linking_disabled",
                error_description="Account linking is not enabled",
            )

        try:
            link_request = InitiateLinkRequest.model_validate_json(
                await request.get_body()
            )
        except (json.JSONDecodeError, ValidationError) as e:
            logger.error("Invalid request body: %s", e)
            return Response.error(
                "invalid_request",
                error_description="Invalid request body",
            )

        if not context.is_valid_redirect_uri(link_request.redirect_uri):
            return Response.error(
                "invalid_redirect_uri",
                error_description="Invalid redirect_uri",
            )

        if not context.is_valid_client_id(link_request.client_id):
            return Response.error(
                "invalid_client",
                error_description="Invalid client_id",
            )

        _, query_params = prepare_authorization(
            provider,
            request,
            context,
            kind=self.kind,
            completion_state={
                "sub_flow": _SUB_LINK,
                "client_id": link_request.client_id,
                "redirect_uri": link_request.redirect_uri,
                "code_challenge": link_request.code_challenge,
                "code_challenge_method": link_request.code_challenge_method,
                "client_state": link_request.state,
                "user_id": str(user.id),
            },
        )

        authorization_url = (
            f"{provider.authorization_endpoint}?{urlencode(query_params)}"
        )

        return Response(
            status_code=200,
            body=InitiateLinkResponse(
                authorization_url=authorization_url
            ).model_dump_json(),
            headers={"Content-Type": "application/json"},
        )

    async def _finalize_link(
        self,
        request: AsyncHTTPRequest,
        context: Context,
        provider: OAuth2Provider,
    ) -> Response:
        """POST /{provider}/finalize-link — SPA confirms the link with PKCE."""
        user = context.get_user_from_request(request)
        if user is None:
            return Response.error(
                "unauthorized",
                error_description="Not logged in",
                status_code=401,
            )

        request_data = json.loads(await request.get_body())
        code = request_data.get("link_code")
        allow_login = request_data.get("allow_login", False) is True

        if not code:
            logger.error("No link code found in request")
            return Response.error(
                "server_error",
                error_description="No link code found in request",
            )

        raw = context.secondary_storage.get(f"oauth:link_request:{code}")
        if not raw:
            logger.error("No link data found in secondary storage")
            return Response.error(
                "server_error",
                error_description="No link data found in secondary storage",
            )

        try:
            link_data = OAuth2LinkCodeData.model_validate_json(raw)
        except ValidationError as e:
            logger.error("Invalid link data", exc_info=e)
            return Response.error(
                "server_error",
                error_description="Invalid link data",
            )

        if link_data.expires_at < datetime.now(tz=timezone.utc):
            logger.error("Link code has expired")
            return Response.error(
                "server_error",
                error_description="Link code has expired",
            )

        if str(user.id) != link_data.user_id:
            logger.error(
                "User ID mismatch: current user %s, link code for %s",
                user.id,
                link_data.user_id,
            )
            return Response.error(
                "unauthorized",
                error_description="Link code does not belong to current user",
                status_code=403,
            )

        if link_data.code_challenge_method != "S256":
            return Response.error(
                "server_error",
                error_description="Unsupported code challenge method",
            )

        code_verifier = request_data.get("code_verifier")
        if not code_verifier:
            return Response.error(
                "server_error",
                error_description="No code_verifier provided",
            )

        if not validate_pkce(
            link_data.code_challenge,
            link_data.code_challenge_method,
            code_verifier,
        ):
            return Response.error(
                "server_error",
                error_description="Invalid code challenge",
            )

        proxy_redirect_uri = build_proxy_redirect_uri(request, context.base_url)

        try:
            exchange_and_attach_social_account(
                user,
                provider,
                context,
                provider_code=link_data.provider_code,
                provider_code_verifier=link_data.provider_code_verifier,
                proxy_redirect_uri=proxy_redirect_uri,
                callback_extra=link_data.provider_callback_extra,
                is_login_method=allow_login,
            )
        except OAuth2Exception as e:
            return Response.error(
                e.error,
                error_description=e.error_description,
            )

        return Response(status_code=200, body='{"message": "Link finalized"}')
