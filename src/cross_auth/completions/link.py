from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, ClassVar
from urllib.parse import urlencode

from cross_web import AsyncHTTPRequest
from pydantic import ValidationError

from .._completion import AuthCompletion, AuthFlowState
from .._context import Context
from .._provider_service import (
    build_proxy_redirect_uri,
    exchange_and_attach_social_account,
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


class LinkCompletion(AuthCompletion):
    """Link an additional social account to an already-authenticated user.

    Initiation is POST with a JSON body (client_id, redirect_uri, code_challenge).
    The endpoint returns a JSON body with the provider authorization URL — the
    SPA performs the redirect. After the provider round-trip, the library
    issues a link code (not a session, not an auth code). The client then
    calls POST /{provider}/finalize-link with the link code + PKCE verifier to
    actually exchange the provider tokens and attach the social account.
    """

    kind: ClassVar[str] = "link"
    entry_methods: ClassVar[list[str]] = ["POST"]

    def entry_path(self, provider_id: str) -> str:
        return f"/{provider_id}/link"

    async def start(
        self,
        request: AsyncHTTPRequest,
        context: Context,
        provider: OAuth2Provider,
    ) -> Response:
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
            logger.error("Invalid redirect_uri: %s", link_request.redirect_uri)
            return Response.error(
                "invalid_redirect_uri",
                error_description="Invalid redirect_uri",
            )

        if not context.is_valid_client_id(link_request.client_id):
            logger.error("Invalid client_id: %s", link_request.client_id)
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

    async def complete(
        self,
        request: AsyncHTTPRequest,
        context: Context,
        provider: OAuth2Provider,
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
            handler = self._build_finalize_handler(provider)
            routes.append(
                Route(
                    path=f"/{provider_id}/finalize-link",
                    methods=["POST"],
                    function=handler,
                    operation_id=f"{provider_id}_finalize_link",
                )
            )
        return routes

    def _build_finalize_handler(self, provider: OAuth2Provider):
        async def handler(request: AsyncHTTPRequest, context: Context) -> Response:
            return await self._finalize_link(request, context, provider)

        return handler

    async def _finalize_link(
        self,
        request: AsyncHTTPRequest,
        context: Context,
        provider: OAuth2Provider,
    ) -> Response:
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
