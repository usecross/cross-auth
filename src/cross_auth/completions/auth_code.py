from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, ClassVar

from cross_web import AsyncHTTPRequest
from pydantic import HttpUrl, TypeAdapter, ValidationError

from .._completion import AuthCompletion, AuthFlowState
from .._context import Context
from .._issuer import AuthorizationCodeGrantData
from .._provider_service import (
    build_proxy_redirect_uri,
    exchange_and_resolve_user,
    prepare_authorization,
)
from ..social_providers.oauth import OAuth2Exception, OAuth2Provider
from ..utils._response import Response

logger = logging.getLogger(__name__)


class AuthCodeCompletion(AuthCompletion):
    """OAuth 2.0 authorization-code flow for third-party clients (SPAs, mobile, etc.).

    The client initiates /{provider}/authorize with PKCE + client_id + redirect_uri.
    After the provider round-trip, the library issues a local authorization code
    and redirects back to the client's redirect_uri. The client exchanges the
    code at POST /token (contributed by the Issuer, mounted separately).
    """

    kind: ClassVar[str] = "authorize"
    entry_methods: ClassVar[list[str]] = ["GET"]

    async def start(
        self,
        request: AsyncHTTPRequest,
        context: Context,
        provider: OAuth2Provider,
    ) -> Response:
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
            logger.error("No response type provided")
            return Response.error_redirect(
                redirect_uri,
                error="invalid_request",
                error_description="No response type provided",
                state=client_state,
            )
        if response_type != "code":
            logger.error("Unsupported response type")
            return Response.error_redirect(
                redirect_uri,
                error="invalid_request",
                error_description="Unsupported response type",
                state=client_state,
            )

        code_challenge = request.query_params.get("code_challenge")
        code_challenge_method = request.query_params.get("code_challenge_method")
        if not code_challenge:
            logger.error("No code challenge provided")
            return Response.error_redirect(
                redirect_uri,
                error="invalid_request",
                error_description="No code challenge provided",
                state=client_state,
            )
        if code_challenge_method != "S256":
            logger.error("Unsupported code challenge method")
            return Response.error_redirect(
                redirect_uri,
                error="invalid_request",
                error_description="Unsupported code challenge method",
                state=client_state,
            )

        client_id = request.query_params.get("client_id")
        if not client_id:
            logger.error("No client_id provided")
            return Response.error_redirect(
                redirect_uri,
                error="invalid_request",
                error_description="No client_id provided",
                state=client_state,
            )
        if not context.is_valid_client_id(client_id):
            logger.error("Invalid client_id: %s", client_id)
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
