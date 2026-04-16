from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, ClassVar, Literal, NotRequired, TypedDict

import httpx
from cross_web import AsyncHTTPRequest
from pydantic import BaseModel, ValidationError

from .._context import Context
from ..models.oauth_token_response import (
    OAuth2TokenEndpointResponse,
    TokenErrorResponse,
    TokenResponse,
)

logger = logging.getLogger(__name__)


class UserInfo(TypedDict, total=True):
    email: str | None
    id: str | int
    email_verified: bool | None
    name: NotRequired[str | None]


@dataclass
class ValidatedUserInfo:
    email: str | None
    provider_user_id: str
    email_verified: bool | None


class TokenExchangeParams(TypedDict, total=False):
    grant_type: str
    code: str
    redirect_uri: str
    client_id: str
    client_secret: str
    code_verifier: str


class OAuth2Exception(Exception):
    def __init__(self, error: str, error_description: str):
        self.error = error
        self.error_description = error_description


class OAuth2LinkCodeData(BaseModel):
    """Persisted between a link-flow provider callback and /finalize-link.

    Owned by LinkCompletion; lives here because the provider class is still
    the natural home for OAuth-specific data shapes used across the package.
    """

    expires_at: datetime
    client_id: str
    redirect_uri: str
    code_challenge: str
    code_challenge_method: Literal["S256"]
    user_id: str
    provider_code: str
    provider_code_verifier: str | None = None
    client_state: str | None = None
    provider_callback_extra: dict[str, Any] | None = None


class InitiateLinkRequest(BaseModel):
    redirect_uri: str
    code_challenge: str
    code_challenge_method: Literal["S256"]
    client_id: str
    state: str | None = None


class InitiateLinkResponse(BaseModel):
    authorization_url: str


class CallbackData(BaseModel):
    """Data extracted from an OAuth callback request."""

    code: str | None
    state: str | None
    error: str | None
    extra: dict[str, Any] | None = None


class OAuth2Provider:
    """Pure provider strategy — the upstream OAuth 2.0 identity provider.

    Responsibilities:
    - build the authorization URL parameters sent to the provider
    - extract the code/state/error from the provider's callback
    - exchange a provider code for provider tokens
    - fetch and validate provider user info

    HTTP routing, state persistence, session/token issuance, and failure
    rendering live in AuthCompletion subclasses and the router — not here.
    """

    id: ClassVar[str]
    authorization_endpoint: ClassVar[str]
    token_endpoint: ClassVar[str]
    user_info_endpoint: ClassVar[str | None]
    scopes: ClassVar[list[str]]
    supports_pkce: ClassVar[bool]

    def __init__(
        self,
        client_id: str,
        client_secret: str | None = None,
        trust_email: bool = True,
    ):
        """
        Args:
            client_id: OAuth2 client ID registered with the provider.
            client_secret: OAuth2 client secret. None for providers that
                generate secrets dynamically (e.g. Apple).
            trust_email: If True, emails from this provider are trusted for
                account linking even without explicit email_verified=True.
                Set to False for providers that don't verify email ownership.
        """
        self.client_id = client_id
        self.client_secret = client_secret
        self.trust_email = trust_email

    def can_auto_link(self, context: Context, email_verified: bool | None) -> bool:
        """Check if auto-linking by email is allowed.

        Requires account_linking.enabled AND either provider is trusted
        (trust_email=True) OR the provider reports email_verified=True.
        """
        account_linking = context.config.get("account_linking", {})
        return account_linking.get("enabled", False) and (
            self.trust_email or email_verified is True
        )

    def allows_different_emails(
        self, context: Context, provider_email: str | None, user_email: str | None
    ) -> bool:
        """Check if linking is allowed when emails differ.

        True if either email is missing, emails match (case-insensitive), or
        allow_different_emails is enabled.
        """
        if not provider_email or not user_email:
            return True
        if provider_email.lower() == user_email.lower():
            return True
        account_linking = context.config.get("account_linking", {})
        return account_linking.get("allow_different_emails", False)

    def get_redirect_params(
        self,
        state: str,
        redirect_uri: str,
        response_type: str = "code",
        **kwargs: str,
    ) -> dict[str, str]:
        """Base query parameters for the provider authorization redirect."""
        return {
            "client_id": self.client_id,
            "scope": " ".join(self.scopes),
            "redirect_uri": redirect_uri,
            "response_type": response_type,
            "state": state,
            **kwargs,
        }

    def build_authorization_params(
        self,
        state: str,
        proxy_redirect_uri: str,
        response_type: str,
        code_challenge: str | None = None,
        code_challenge_method: str | None = None,
        login_hint: str | None = None,
    ) -> dict[str, str]:
        """Build authorization request parameters.

        Override to customize — e.g. force a specific response_type or
        add provider-specific extras.
        """
        params = self.get_redirect_params(
            state=state,
            redirect_uri=proxy_redirect_uri,
            response_type=response_type,
        )
        if code_challenge:
            params["code_challenge"] = code_challenge
        if code_challenge_method:
            params["code_challenge_method"] = code_challenge_method
        if login_hint:
            params["login_hint"] = login_hint
        return params

    async def extract_callback_data(self, request: AsyncHTTPRequest) -> CallbackData:
        """Extract code, state, and error from the callback request.

        Override for providers that use POST (e.g., Apple with
        response_mode=form_post).
        """
        return CallbackData(
            code=request.query_params.get("code"),
            state=request.query_params.get("state"),
            error=request.query_params.get("error"),
        )

    def build_token_exchange_params(
        self, code: str, redirect_uri: str, code_verifier: str | None = None
    ) -> TokenExchangeParams:
        """Build token exchange request parameters.

        Override to customize token exchange parameters.
        """
        params: TokenExchangeParams = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": self.client_id,
        }
        if self.client_secret:
            params["client_secret"] = self.client_secret
        if code_verifier:
            params["code_verifier"] = code_verifier
        return params

    def send_token_request(self, data: TokenExchangeParams) -> httpx.Response:
        """Send the token exchange request. Override to customize transport."""
        return httpx.post(
            self.token_endpoint,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            data=data,
        )

    def parse_token_response(
        self, response: httpx.Response
    ) -> OAuth2TokenEndpointResponse:
        """Parse the token exchange response. Override for non-JSON formats.

        Raises:
            OAuth2Exception: If the response cannot be parsed.
        """
        try:
            return OAuth2TokenEndpointResponse.model_validate_json(response.text)
        except ValidationError as e:
            logger.error("Failed to parse token response: %s", e)
            raise OAuth2Exception(
                error="server_error",
                error_description="Failed to parse token response",
            ) from e

    def exchange_code(
        self,
        code: str,
        redirect_uri: str,
        code_verifier: str | None = None,
    ) -> TokenResponse:
        """Exchange an authorization code for provider tokens.

        Raises:
            OAuth2Exception: If the token exchange fails.
        """
        try:
            params = self.build_token_exchange_params(code, redirect_uri, code_verifier)
            response = self.send_token_request(params)
            response.raise_for_status()
            token_response = self.parse_token_response(response)

            if token_response.is_error():
                if not isinstance(token_response.root, TokenErrorResponse):
                    raise OAuth2Exception(
                        error="server_error",
                        error_description="Unexpected token response format",
                    )
                logger.error("Token exchange failed: %s", token_response.root.error)
                raise OAuth2Exception(
                    error="server_error",
                    error_description=(
                        f"Token exchange failed: {token_response.root.error}"
                    ),
                )

            if not isinstance(token_response.root, TokenResponse):
                raise OAuth2Exception(
                    error="server_error",
                    error_description="Unexpected token response format",
                )

            logger.debug(
                "Token exchange succeeded (token_type=%s, scope=%s, expires_in=%s)",
                token_response.root.token_type,
                token_response.root.scope,
                token_response.root.expires_in,
            )
            return token_response.root

        except httpx.HTTPStatusError as e:
            logger.warning(
                "HTTP error during token exchange: %s - %s",
                e.response.status_code,
                e.response.text,
            )
            raise OAuth2Exception(
                error="server_error",
                error_description="Token exchange failed",
            ) from e
        except (httpx.RequestError, ValidationError) as e:
            logger.error("Failed to exchange code for token: %s", e)
            raise OAuth2Exception(
                error="server_error",
                error_description="Failed to exchange code for token",
            ) from e

    def get_user_info(
        self,
        token_response: TokenResponse,
        context: Context,
        extra: dict[str, Any] | None = None,
    ) -> UserInfo:
        """Fetch user info after token exchange.

        Default fetches from the userinfo endpoint with the access token.
        Override for providers that include user info in the token response
        (e.g., OIDC providers) or that need extra calls (e.g., GitHub emails).
        """
        if not self.user_info_endpoint:
            raise NotImplementedError(
                f"{self.__class__.__name__} does not have a user_info_endpoint. "
                "Override get_user_info() instead."
            )

        try:
            response = httpx.get(
                self.user_info_endpoint,
                headers={"Authorization": f"Bearer {token_response.access_token}"},
            )
            response.raise_for_status()
            user_info = response.json()
        except httpx.HTTPStatusError as e:
            logger.error(
                "Failed to fetch user info from %s: %s (status=%d, body=%s, scope=%s)",
                self.user_info_endpoint,
                e,
                e.response.status_code,
                e.response.text,
                token_response.scope,
            )
            raise OAuth2Exception(
                error="server_error",
                error_description="Failed to fetch user info",
            ) from e
        except Exception as e:
            logger.error(
                "Failed to fetch user info from %s: %s (scope=%s)",
                self.user_info_endpoint,
                e,
                token_response.scope,
            )
            raise OAuth2Exception(
                error="server_error",
                error_description="Failed to fetch user info",
            ) from e

        return user_info

    def validate_user_info(self, user_info: UserInfo) -> ValidatedUserInfo:
        """Extract and validate email + provider user id.

        Raises:
            OAuth2Exception: If email or provider_user_id is missing.
        """
        email = user_info.get("email")
        if not email:
            logger.error("No email found in user info")
            raise OAuth2Exception(
                error="server_error",
                error_description="No email found in user info",
            )

        provider_user_id = user_info.get("id")
        if not provider_user_id:
            logger.error("No provider user ID found in user info")
            raise OAuth2Exception(
                error="server_error",
                error_description="No provider user ID found in user info",
            )

        return ValidatedUserInfo(
            email=email,
            provider_user_id=str(provider_user_id),
            email_verified=user_info.get("email_verified"),
        )
