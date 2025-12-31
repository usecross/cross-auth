import json
import logging
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, ClassVar, Literal, TypedDict, cast

import httpx
from lia import AsyncHTTPRequest
from pydantic import BaseModel, HttpUrl, TypeAdapter, ValidationError

from cross_auth.exceptions import CrossAuthException
from cross_auth.utils._pkce import (
    calculate_s256_challenge,
    generate_code_verifier,
    validate_pkce,
)
from cross_auth.utils._response import Response
from cross_auth.utils._url import construct_relative_url

from .._context import Context
from .._issuer import AuthorizationCodeGrantData
from .._route import Route
from .._storage import User
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


@dataclass
class ValidatedUserInfo:
    email: str
    provider_user_id: str
    email_verified: bool | None


class OAuth2Exception(Exception):
    def __init__(self, error: str, error_description: str):
        self.error = error
        self.error_description = error_description


class OAuth2AuthorizationRequestData(BaseModel):
    redirect_uri: str
    login_hint: str | None
    client_state: str | None
    state: str
    code_challenge: str
    code_challenge_method: Literal["S256"]
    link: bool = False
    user_id: str | None = None  # User who initiated the link flow
    provider_code_verifier: str | None = None  # PKCE verifier for provider OAuth flow


class OAuth2LinkCodeData(BaseModel):
    expires_at: datetime
    client_id: str
    redirect_uri: str
    code_challenge: str
    code_challenge_method: Literal["S256"]
    user_id: str  # User who initiated the link flow
    provider_code: str
    provider_code_verifier: str | None = None
    client_state: str | None = None


class OAuth2Provider:
    id: ClassVar[str]
    authorization_endpoint: ClassVar[str]
    token_endpoint: ClassVar[str]
    user_info_endpoint: ClassVar[str]
    scopes: ClassVar[list[str]]
    supports_pkce: ClassVar[bool]

    def __init__(self, client_id: str, client_secret: str, trust_email: bool = True):
        """
        Initialize the OAuth2 provider.

        Args:
            client_id: OAuth2 client ID.
            client_secret: OAuth2 client secret.
            trust_email: If True, emails from this provider are trusted for account
                linking even without explicit email_verified=True. Set to False for
                providers that don't verify email ownership.
        """
        self.client_id = client_id
        self.client_secret = client_secret
        self.trust_email = trust_email

    def _generate_code(self) -> str:
        return str(uuid.uuid4())

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

    def get_redirect_params(
        self, state: str, redirect_uri: str, response_type: str = "code", **kwargs: str
    ) -> dict[str, str]:
        """
        Generate the query parameters for the redirect to the authorization endpoint.
        """
        return {
            "client_id": self.client_id,
            "scope": " ".join(self.scopes),
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "state": state,
            **kwargs,
        }

    async def authorize(
        self,
        request: AsyncHTTPRequest,
        context: Context,
    ) -> Response:
        """
        Redirect to the provider's authorization page.

        This endpoint works similar to a proxy, we store the actual redirect uri
        in a cookie and then use that to redirect the user back to the client
        once the authorization is complete on the Identity Provider's site.
        """

        redirect_uri = request.query_params.get("redirect_uri")

        if not redirect_uri:
            logger.error("No redirect URI provided")
            return Response.error("invalid_request")

        try:
            redirect_uri = str(TypeAdapter(HttpUrl).validate_python(redirect_uri))
        except ValidationError:
            logger.error("Invalid redirect URI")

            return Response.error("invalid_redirect_uri")

        # TODO: this is where we'll validate the redirect URI against the client
        # when we implement clients :)

        if not context.is_valid_redirect_uri(redirect_uri):
            logger.error("Invalid redirect URI")

            return Response.error("invalid_redirect_uri")

        # Capture client_state early for CSRF protection in error redirects
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

        if response_type not in ["code", "link_code"]:
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

        login_hint = request.query_params.get("login_hint")
        state = secrets.token_hex(16)

        # For link flows, capture the user_id to ensure only the initiating user can finalize
        user_id: str | None = None
        if response_type == "link_code":
            if not (user := context.get_user_from_request(request)):
                logger.error("User must be authenticated to initiate link flow")
                return Response.error_redirect(
                    redirect_uri,
                    error="unauthorized",
                    error_description="User must be authenticated to initiate link flow",
                    state=client_state,
                )

            # Fail fast if account linking is disabled
            account_linking = context.config.get("account_linking", {})
            if not account_linking.get("enabled", False):
                logger.error("Account linking is not enabled")
                return Response.error_redirect(
                    redirect_uri,
                    error="linking_disabled",
                    error_description="Account linking is not enabled",
                    state=client_state,
                )

            user_id = str(user.id)

        provider_code_verifier: str | None = None
        provider_code_challenge: str | None = None
        provider_code_challenge_method: str | None = None

        if self.supports_pkce:
            provider_code_verifier = generate_code_verifier()
            provider_code_challenge = calculate_s256_challenge(provider_code_verifier)
            provider_code_challenge_method = "S256"

        data = OAuth2AuthorizationRequestData.model_validate(
            {
                "redirect_uri": redirect_uri,
                "login_hint": login_hint,
                "client_state": client_state,
                "state": state,
                "code_challenge": code_challenge,
                "code_challenge_method": code_challenge_method,
                "link": response_type == "link_code",
                "user_id": user_id,
                "provider_code_verifier": provider_code_verifier,
            }
        )

        context.secondary_storage.set(
            f"oauth:authorization_request:{state}",
            data.model_dump_json(),
            # TODO: ttl
        )

        proxy_redirect_uri = construct_relative_url(
            str(request.url), "callback", context.base_url
        )

        query_params = self.build_authorization_params(
            state=state,
            proxy_redirect_uri=proxy_redirect_uri,
            response_type="code",
            code_challenge=provider_code_challenge,
            code_challenge_method=provider_code_challenge_method,
            login_hint=login_hint,
        )

        return Response.redirect(
            self.authorization_endpoint,
            query_params=query_params,
        )

    async def callback(self, request: AsyncHTTPRequest, context: Context) -> Response:
        """
        This callback endpoint is used to exchange the Identity Provider's code
        for a token and then login the user on our side.
        """

        state = request.query_params.get("state")

        if not state:
            logger.error("No state found in request")
            return Response.error(
                "server_error",
                error_description="No state found in request",
            )

        raw_provider_data = context.secondary_storage.get(
            f"oauth:authorization_request:{state}"
        )

        if not raw_provider_data:
            logger.error("No provider data found in secondary storage")

            return Response.error(
                "server_error",
                error_description="Provider data not found",
            )

        try:
            provider_data = OAuth2AuthorizationRequestData.model_validate_json(
                raw_provider_data
            )
        except ValidationError as e:
            logger.error("Invalid provider data", exc_info=e)

            return Response.error(
                "server_error",
                error_description="Invalid provider data",
            )

        code = request.query_params.get("code")

        if not code:
            logger.error("No authorization code received in callback")

            return Response.error_redirect(
                provider_data.redirect_uri,
                error="server_error",
                error_description="No authorization code received in callback",
                state=provider_data.client_state,
            )

        if provider_data.link:
            return self._link_flow(request, context, provider_data, code)

        redirect_uri = provider_data.redirect_uri

        proxy_redirect_uri = construct_relative_url(
            str(request.url), "callback", context.base_url
        )

        try:
            token_response = self.exchange_code(
                code, proxy_redirect_uri, provider_data.provider_code_verifier
            )

            user_info = self.fetch_user_info(token_response.access_token)
            validated = self.validate_user_info(user_info)
        except OAuth2Exception as e:
            return Response.error_redirect(
                redirect_uri,
                error=e.error,
                error_description=e.error_description,
                state=provider_data.client_state,
            )

        social_account = context.accounts_storage.find_social_account(
            provider=self.id,
            provider_user_id=validated.provider_user_id,
        )

        if social_account:
            context.accounts_storage.update_social_account(
                social_account.id,
                access_token=token_response.access_token,
                refresh_token=token_response.refresh_token,
                access_token_expires_at=token_response.access_token_expires_at,
                refresh_token_expires_at=token_response.refresh_token_expires_at,
                scope=token_response.scope,
                user_info=cast(dict[str, Any], user_info),
                provider_email=validated.email,
                provider_email_verified=validated.email_verified,
            )

            user = context.accounts_storage.find_user_by_id(social_account.user_id)
            assert user is not None, "User not found for social account"
        else:
            user: User | None = None

            if self.can_auto_link(context, validated.email_verified):
                user = context.accounts_storage.find_user_by_email(validated.email)

            if not user:
                # Check if email exists but auto-linking wasn't allowed
                existing_user = context.accounts_storage.find_user_by_email(
                    validated.email
                )
                if existing_user:
                    return Response.error_redirect(
                        redirect_uri,
                        error="account_not_linked",
                        error_description="An account with this email exists but could not be linked automatically.",
                        state=provider_data.client_state,
                    )

                try:
                    user = context.accounts_storage.create_user(
                        user_info=cast(dict[str, Any], user_info),
                        email=validated.email,
                        email_verified=validated.email_verified or False,
                    )
                except CrossAuthException as e:
                    return Response.error_redirect(
                        redirect_uri,
                        error=e.error,
                        error_description=e.error_description,
                        state=provider_data.client_state,
                    )

            context.accounts_storage.create_social_account(
                user_id=user.id,
                provider=self.id,
                provider_user_id=validated.provider_user_id,
                access_token=token_response.access_token,
                refresh_token=token_response.refresh_token,
                access_token_expires_at=token_response.access_token_expires_at,
                refresh_token_expires_at=token_response.refresh_token_expires_at,
                scope=token_response.scope,
                user_info=cast(dict[str, Any], user_info),
                provider_email=validated.email,
                provider_email_verified=validated.email_verified,
                is_login_method=True,
            )

        code = self._generate_code()

        data = AuthorizationCodeGrantData(
            user_id=str(user.id),
            expires_at=datetime.now(tz=timezone.utc) + timedelta(minutes=10),
            client_id=self.client_id,
            redirect_uri=redirect_uri,
            code_challenge=provider_data.code_challenge,
            code_challenge_method=provider_data.code_challenge_method,
        )

        context.secondary_storage.set(
            f"oauth:code:{code}",
            data.model_dump_json(),
        )

        # Include client_state in redirect for CSRF protection
        query_params = {"code": code}
        if provider_data.client_state:
            query_params["state"] = provider_data.client_state

        return Response.redirect(
            redirect_uri,
            query_params=query_params,
        )

    def _link_flow(
        self,
        request: AsyncHTTPRequest,
        context: Context,
        provider_data: OAuth2AuthorizationRequestData,
        provider_code: str,
    ) -> Response:
        # user_id should always be present for link flows (validated in authorize)
        if not provider_data.user_id:
            logger.error("No user_id in provider_data for link flow")
            return Response.error_redirect(
                provider_data.redirect_uri,
                error="server_error",
                error_description="Invalid link flow data",
                state=provider_data.client_state,
            )

        data = OAuth2LinkCodeData(
            expires_at=datetime.now(tz=timezone.utc) + timedelta(minutes=10),
            client_id=self.client_id,
            redirect_uri=provider_data.redirect_uri,
            code_challenge=provider_data.code_challenge,
            code_challenge_method=provider_data.code_challenge_method,
            user_id=provider_data.user_id,
            provider_code=provider_code,
            provider_code_verifier=provider_data.provider_code_verifier,
            client_state=provider_data.client_state,
        )

        code = self._generate_code()

        context.secondary_storage.set(
            f"oauth:link_request:{code}",
            data.model_dump_json(),
        )

        return Response.redirect(
            provider_data.redirect_uri,
            query_params={"link_code": code},
        )

    def build_authorization_params(
        self,
        state: str,
        proxy_redirect_uri: str,
        response_type: str,
        code_challenge: str | None = None,
        code_challenge_method: str | None = None,
        login_hint: str | None = None,
    ) -> dict:
        """Build authorization request parameters.

        Override this method to customize authorization parameters.
        For example, to force a specific response_type or add extra params.
        """
        params = self.get_redirect_params(
            state=state, redirect_uri=proxy_redirect_uri, response_type=response_type
        )

        if code_challenge:
            params["code_challenge"] = code_challenge

        if code_challenge_method:
            params["code_challenge_method"] = code_challenge_method

        if login_hint:
            params["login_hint"] = login_hint

        return params

    def build_token_exchange_params(
        self, code: str, redirect_uri: str, code_verifier: str | None = None
    ) -> dict:
        """Build token exchange request parameters.

        Override this method to customize token exchange parameters.
        """
        params = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }

        if code_verifier:
            params["code_verifier"] = code_verifier

        return params

    def send_token_request(self, data: dict[str, Any]) -> httpx.Response:
        """Send token exchange request.

        Override this method to customize how the request is sent
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
    ) -> OAuth2TokenEndpointResponse | None:
        """Parse token exchange response.

        Override this method to handle different response formats
        (e.g., JSON instead of query string).
        """
        try:
            return OAuth2TokenEndpointResponse.model_validate_json(response.text)
        except ValidationError as e:
            logger.error(f"Failed to parse token response: {str(e)}")
            return None

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

            if token_response is None:
                logger.error("Failed to parse token response")
                raise OAuth2Exception(
                    error="server_error",
                    error_description="Failed to parse token response",
                )

            if token_response.is_error():
                assert isinstance(token_response.root, TokenErrorResponse)

                logger.error(f"Token exchange failed: {token_response.root.error}")

                raise OAuth2Exception(
                    error="server_error",
                    error_description=f"Token exchange failed: {token_response.root.error}",
                )

            assert isinstance(token_response.root, TokenResponse)
            return token_response.root

        except httpx.HTTPStatusError as e:
            logger.warning(
                f"HTTP error during token exchange: {e.response.status_code} - {e.response.text}"
            )
            raise OAuth2Exception(
                error="server_error",
                error_description="Token exchange failed",
            ) from e
        except (httpx.RequestError, ValidationError) as e:
            logger.error(f"Failed to exchange code for token: {str(e)}")
            raise OAuth2Exception(
                error="server_error",
                error_description="Failed to exchange code for token",
            ) from e

    def fetch_user_info(self, access_token: str) -> UserInfo:
        try:
            response = httpx.get(
                self.user_info_endpoint,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            response.raise_for_status()
            user_info = response.json()
        except Exception as e:
            logger.error(f"Failed to fetch user info: {str(e)}")
            raise OAuth2Exception(
                error="server_error",
                error_description="Failed to fetch user info",
            )

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

    async def finalize_link(
        self, request: AsyncHTTPRequest, context: Context
    ) -> Response:
        if not (user := context.get_user_from_request(request)):
            return Response.error(
                "unauthorized",
                error_description="Not logged in",
                status_code=401,
            )

        request_data = json.loads(await request.get_body())
        code = request_data.get("link_code")
        allow_login_raw = request_data.get("allow_login", False)
        allow_login = allow_login_raw is True  # Strict boolean check

        if not code:
            logger.error("No link code found in request")

            return Response.error(
                "server_error",
                error_description="No link code found in request",
            )

        data = context.secondary_storage.get(f"oauth:link_request:{code}")

        if not data:
            logger.error("No link data found in secondary storage")

            return Response.error(
                "server_error",
                error_description="No link data found in secondary storage",
            )

        try:
            link_data = OAuth2LinkCodeData.model_validate_json(data)
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

        # Verify that the link code belongs to the current user
        # This prevents account takeover where an attacker tricks a victim
        # into using the attacker's link code
        if str(user.id) != link_data.user_id:
            logger.error(
                f"User ID mismatch: current user {user.id}, link code for {link_data.user_id}"
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

        proxy_redirect_uri = construct_relative_url(
            str(request.url), "callback", context.base_url
        )

        try:
            token_response = self.exchange_code(
                link_data.provider_code,
                proxy_redirect_uri,
                link_data.provider_code_verifier,
            )

            user_info = self.fetch_user_info(token_response.access_token)
            validated = self.validate_user_info(user_info)
        except OAuth2Exception as e:
            return Response.error(
                e.error,
                error_description=e.error_description,
            )

        # Manual linking requires: enabled AND (trusted OR verified)
        account_linking = context.config.get("account_linking", {})

        if not account_linking.get("enabled", False):
            return Response.error(
                "linking_disabled",
                error_description="Account linking is not enabled.",
            )

        if not self.trust_email and validated.email_verified is not True:
            return Response.error(
                "email_not_verified",
                error_description="Cannot link account: email not verified by provider.",
            )

        if not self.allows_different_emails(context, validated.email, user.email):
            return Response.error(
                "email_mismatch",
                error_description="Provider email does not match account email.",
            )

        social_account = context.accounts_storage.find_social_account(
            provider=self.id,
            provider_user_id=validated.provider_user_id,
        )

        if social_account:
            if social_account.user_id != user.id:
                return Response.error(
                    "server_error",
                    error_description="Social account already exists",
                )

            context.accounts_storage.update_social_account(
                social_account.id,
                access_token=token_response.access_token,
                refresh_token=token_response.refresh_token,
                access_token_expires_at=token_response.access_token_expires_at,
                refresh_token_expires_at=token_response.refresh_token_expires_at,
                scope=token_response.scope,
                user_info=cast(dict[str, Any], user_info),
                provider_email=validated.email,
                provider_email_verified=validated.email_verified,
            )
        else:
            context.accounts_storage.create_social_account(
                user_id=user.id,
                provider=self.id,
                provider_user_id=validated.provider_user_id,
                access_token=token_response.access_token,
                refresh_token=token_response.refresh_token,
                access_token_expires_at=token_response.access_token_expires_at,
                refresh_token_expires_at=token_response.refresh_token_expires_at,
                scope=token_response.scope,
                user_info=cast(dict[str, Any], user_info),
                provider_email=validated.email,
                provider_email_verified=validated.email_verified,
                is_login_method=allow_login,
            )

        return Response(status_code=200, body='{"message": "Link finalized"}')

    @property
    def routes(self) -> list[Route]:
        # TODO: add support for response models (for OpenAPI)
        return [
            Route(
                path=f"/{self.id}/authorize",
                methods=["GET"],
                function=self.authorize,
                operation_id=f"{self.id}_authorize",
            ),
            Route(
                path=f"/{self.id}/callback",
                methods=["GET"],
                function=self.callback,
                operation_id=f"{self.id}_callback",
            ),
            Route(
                path=f"/{self.id}/finalize-link",
                methods=["POST"],
                function=self.finalize_link,
                operation_id=f"{self.id}_finalize_link",
            ),
        ]
