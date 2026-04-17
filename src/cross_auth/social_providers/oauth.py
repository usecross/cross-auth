import logging
from dataclasses import dataclass
from urllib.parse import urlencode
from typing import Any, ClassVar, TypedDict, NotRequired

import httpx
from cross_web import AsyncHTTPRequest
from pydantic import BaseModel, ValidationError

from cross_auth.utils._response import Response  # noqa: F401  (re-exported for subclasses)

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


class CallbackData(BaseModel):
    """Data extracted from an OAuth callback request."""

    code: str | None
    state: str | None
    error: str | None
    extra: dict[str, Any] | None = None  # Provider-specific data


class OAuth2Provider:
    """Pure OAuth2 authentication logic for a single identity provider.

    Providers no longer own HTTP routes — the router (see `_auth_flow.py`)
    orchestrates HTTP work and calls these primitives.
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
        Initialize the OAuth2 provider.

        Args:
            client_id: OAuth2 client ID.
            client_secret: OAuth2 client secret. None for providers that generate
                secrets dynamically (e.g., Apple).
            trust_email: If True, emails from this provider are trusted for account
                linking even without explicit email_verified=True. Set to False for
                providers that don't verify email ownership.
        """
        self.client_id = client_id
        self.client_secret = client_secret
        self.trust_email = trust_email

    # ---- Account-linking policy ----------------------------------------

    def can_auto_link(self, context: Context, email_verified: bool | None) -> bool:
        """Check if auto-linking by email is allowed.

        Auto-linking requires account linking to be enabled AND either:
        - The provider is trusted (trust_email=True), OR
        - The email is verified by the provider
        """
        account_linking = context.config.get("account_linking", {})

        return account_linking.get("enabled", False) and (
            self.trust_email or email_verified is True
        )

    def allows_different_emails(
        self, context: Context, provider_email: str | None, user_email: str | None
    ) -> bool:
        """Check if linking is allowed when emails differ.

        Returns True if:
        - Either email is missing (no comparison possible), OR
        - Emails match (case-insensitive), OR
        - allow_different_emails is enabled
        """
        if not provider_email or not user_email:
            return True

        if provider_email.lower() == user_email.lower():
            return True

        account_linking = context.config.get("account_linking", {})
        return account_linking.get("allow_different_emails", False)

    # ---- Authorization URL construction --------------------------------

    def build_authorization_params(
        self,
        state: str,
        redirect_uri: str,
        *,
        code_challenge: str | None = None,
        code_challenge_method: str | None = None,
        login_hint: str | None = None,
    ) -> dict[str, str]:
        """Build the query-string params sent to the provider's authorization endpoint.

        Override for providers that need different params (e.g., Apple uses
        response_mode=form_post and space-separated scopes).
        """
        params: dict[str, str] = {
            "client_id": self.client_id,
            "scope": " ".join(self.scopes),
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "state": state,
        }

        if code_challenge:
            params["code_challenge"] = code_challenge

        if code_challenge_method:
            params["code_challenge_method"] = code_challenge_method

        if login_hint:
            params["login_hint"] = login_hint

        return params

    def build_authorization_url(
        self,
        state: str,
        redirect_uri: str,
        *,
        code_challenge: str | None = None,
        code_challenge_method: str | None = None,
        login_hint: str | None = None,
    ) -> str:
        """Return the full URL to redirect the user to at the provider."""
        params = self.build_authorization_params(
            state=state,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            login_hint=login_hint,
        )
        return f"{self.authorization_endpoint}?{urlencode(params)}"

    # ---- Callback parsing ----------------------------------------------

    async def extract_callback_params(self, request: AsyncHTTPRequest) -> CallbackData:
        """Extract code, state, and error from callback request.

        Override for providers that use POST (e.g., Apple with response_mode=form_post).
        """
        return CallbackData(
            code=request.query_params.get("code"),
            state=request.query_params.get("state"),
            error=request.query_params.get("error"),
        )

    # ---- Token exchange -------------------------------------------------

    def build_token_exchange_params(
        self, code: str, redirect_uri: str, code_verifier: str | None = None
    ) -> TokenExchangeParams:
        """Build token exchange request parameters.

        Override this method to customize token exchange parameters.
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
        """Send token exchange request.

        Override this method to customize how the request is sent.
        """
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
        """Parse token exchange response.

        Override this method to handle different response formats.

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
        """Exchange authorization code for tokens.

        Args:
            code: The authorization code to exchange
            redirect_uri: The redirect URI used in the authorization request
            code_verifier: Optional PKCE code verifier

        Raises:
            OAuth2Exception: If the token exchange fails
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
                    error_description=f"Token exchange failed: {token_response.root.error}",
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

    # ---- User info ------------------------------------------------------

    def fetch_user_info(
        self,
        token_response: TokenResponse,
        context: Context,
        extra: dict[str, Any] | None = None,
    ) -> UserInfo:
        """Fetch user info after token exchange.

        Default implementation fetches from the userinfo endpoint using the access token.
        Override for providers that include user info in the token response (e.g., OIDC providers).

        Args:
            token_response: The token response from the provider.
            context: The request context.
            extra: Optional provider-specific data from extract_callback_params.
        """
        if not self.user_info_endpoint:
            raise NotImplementedError(
                f"{self.__class__.__name__} does not have a user_info_endpoint. "
                "Override fetch_user_info() instead."
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
        """
        Validate and extract user info from provider response.

        Raises:
            OAuth2Exception: If email or provider_user_id is missing
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
