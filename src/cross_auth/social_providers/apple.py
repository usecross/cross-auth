import json
import logging
import time
from typing import TYPE_CHECKING, Annotated, Any, Literal

import httpx
import jwt
from cross_web import AsyncHTTPRequest
from pydantic import BaseModel, EmailStr, Field, ValidationError, field_validator

from cross_auth._context import Context
from cross_auth.models.oauth_token_response import (
    OAuth2TokenEndpointResponse,
    TokenResponse,
)

from .oauth import (
    CallbackData,
    OAuth2Exception,
    TokenExchangeParams,
    UserInfo,
    ValidatedUserInfo,
)
from .oidc import OIDCProvider

if TYPE_CHECKING:
    from cross_auth._storage import SecondaryStorage

logger = logging.getLogger(__name__)

_REAL_USER_STATUS_MAP: dict[int, Literal["unsupported", "unknown", "likely_real"]] = {
    0: "unsupported",
    1: "unknown",
    2: "likely_real",
}


class AppleAuthConfig(BaseModel):
    client_id: Annotated[str, Field(description="Service ID from Apple Developer")]
    team_id: Annotated[str, Field(description="10-character Team ID")]
    key_id: Annotated[str, Field(description="Key ID for the private key")]
    private_key: Annotated[str, Field(description="PEM-encoded ES256 private key")]


class AppleIdTokenPayload(BaseModel):
    iss: Literal["https://appleid.apple.com"]
    sub: str
    aud: str
    iat: int
    exp: int
    email: EmailStr | None = None
    email_verified: bool = False
    is_private_email: bool = False
    auth_time: int | None = None
    nonce: str | None = None
    nonce_supported: bool | None = None
    real_user_status: Literal["unsupported", "unknown", "likely_real"] | None = None
    # transfer_sub is only present during the 60-day window after an app is
    # transferred between developer teams. It maps users from old to new team.
    # We parse it but don't handle migration - implement if you need app transfers.
    # See: https://developer.apple.com/documentation/technotes/tn3159
    transfer_sub: str | None = None

    @field_validator("email_verified", "is_private_email", mode="before")
    @classmethod
    def parse_apple_bool_string(cls, v: str | bool | None) -> bool:
        """Parse Apple's string booleans ("true"/"false") to actual booleans.

        Apple's id_token JSON contains these as strings, e.g.:
        {"email_verified": "true", "is_private_email": "false"}
        """

        if v is None:
            return False

        if isinstance(v, bool):
            return v

        if isinstance(v, str):
            return v.lower() == "true"

        return False

    @field_validator("real_user_status", mode="before")
    @classmethod
    def parse_real_user_status(
        cls, v: int | str | None
    ) -> Literal["unsupported", "unknown", "likely_real"] | None:
        """Convert Apple's integer real_user_status to descriptive string.

        Apple sends: 0=unsupported, 1=unknown, 2=likely_real
        """
        if v is None:
            return None

        if isinstance(v, str):
            return v  # type: ignore  # Already a string, assume valid

        result = _REAL_USER_STATUS_MAP.get(v)

        if result is None:
            raise ValueError(f"Invalid real_user_status value: {v}")

        return result


class AppleUserName(BaseModel):
    """User name from first-time authorization."""

    model_config = {"populate_by_name": True}

    first_name: Annotated[str | None, Field(default=None, alias="firstName")]
    last_name: Annotated[str | None, Field(default=None, alias="lastName")]


class AppleFirstTimeUserData(BaseModel):
    """User data sent only on first authorization (in POST form field)."""

    name: AppleUserName | None = None
    email: EmailStr | None = None


class AppleProvider(OIDCProvider):
    """Apple Sign In OAuth2 Provider.

    Key differences from standard OAuth:
    - client_secret is a JWT signed with your private key (ES256)
    - No userinfo endpoint - all data in id_token
    - Email/name only on first authorization
    - Uses POST callback (response_mode=form_post)
    """

    id = "apple"

    authorization_endpoint = "https://appleid.apple.com/auth/authorize"
    token_endpoint = "https://appleid.apple.com/auth/token"

    # OIDC configuration
    jwks_uri = "https://appleid.apple.com/auth/keys"
    issuer = "https://appleid.apple.com"
    jwks_cache_key = "apple:jwks"

    scopes = ["name", "email"]
    supports_pkce = True

    def __init__(self, config: AppleAuthConfig):
        self.config = config
        # client_secret is generated dynamically as JWT
        super().__init__(
            client_id=config.client_id,
            client_secret="",  # Will be overridden per-request
        )

    def generate_client_secret(self) -> str:
        """Generate a JWT client secret for Apple.

        Apple requires client_secret to be a JWT signed with ES256.
        Max validity is 6 months (180 days).
        """
        now = int(time.time())

        headers = {"kid": self.config.key_id, "alg": "ES256"}

        payload = {
            "iss": self.config.team_id,
            "iat": now,
            "exp": now + (86400 * 180),  # 180 days max
            "aud": "https://appleid.apple.com",
            "sub": self.config.client_id,
        }

        return jwt.encode(
            payload, self.config.private_key, algorithm="ES256", headers=headers
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
        """Build authorization request parameters for Apple.

        IMPORTANT: scope must be space-separated ("name email"), NOT plus-encoded.
        """
        params = {
            "client_id": self.config.client_id,
            "redirect_uri": proxy_redirect_uri,
            "response_type": "code",
            "scope": "name email",  # Space-separated, NOT "name+email"
            "state": state,
            "response_mode": "form_post",  # Required for scope to work
        }

        if code_challenge:
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = code_challenge_method or "S256"

        return params

    def build_token_exchange_params(
        self, code: str, redirect_uri: str, code_verifier: str | None = None
    ) -> TokenExchangeParams:
        """Build token exchange parameters with dynamic client_secret JWT."""
        params: TokenExchangeParams = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": self.config.client_id,
            "client_secret": self.generate_client_secret(),
        }

        if code_verifier:
            params["code_verifier"] = code_verifier

        return params

    def validate_id_token(
        self, id_token: str, secondary_storage: "SecondaryStorage"
    ) -> AppleIdTokenPayload:
        """Validate Apple's id_token and parse into AppleIdTokenPayload.

        Uses parent's JWT validation, then parses claims into typed model.
        """
        claims = super().validate_id_token(id_token, secondary_storage)
        return AppleIdTokenPayload.model_validate(claims)

    def extract_user_info(
        self,
        id_token_payload: AppleIdTokenPayload,
        first_time_user_data: AppleFirstTimeUserData | None = None,
    ) -> UserInfo:
        """Extract standardized user info from Apple's id_token.

        Args:
            id_token_payload: Parsed id_token claims
            first_time_user_data: User data from first authorization (name, email)
        """
        user_info: UserInfo = {
            "id": id_token_payload.sub,
            "email": id_token_payload.email,
        }

        # Add extra Apple-specific fields (already parsed as proper booleans)
        user_info["email_verified"] = id_token_payload.email_verified
        user_info["is_private_email"] = id_token_payload.is_private_email

        # Merge first-time user data if available (only on first auth)
        if first_time_user_data:
            if first_time_user_data.name:
                user_info["first_name"] = first_time_user_data.name.first_name
                user_info["last_name"] = first_time_user_data.name.last_name
            # Email from user data takes precedence if present
            if first_time_user_data.email:
                user_info["email"] = first_time_user_data.email

        return user_info

    def validate_user_info(self, user_info: UserInfo) -> ValidatedUserInfo:
        """Validate and extract email and provider user ID.

        Note: Email may be None on subsequent logins (Apple only sends on first auth).
        The provider_user_id (sub) is always available.
        """
        provider_user_id = user_info.get("id")

        if not provider_user_id:
            raise OAuth2Exception(
                error="server_error",
                error_description="No user ID (sub) found in id_token",
            )

        # Email may be None on subsequent logins - that's expected
        email = user_info.get("email")

        return ValidatedUserInfo(
            email=email,
            provider_user_id=str(provider_user_id),
            email_verified=user_info.get("email_verified"),
        )

    async def extract_callback_data(self, request: AsyncHTTPRequest) -> CallbackData:
        """Extract callback data from Apple's POST form data.

        Apple uses response_mode=form_post, so callback data comes via POST.
        Also extracts the `user` field (first-time user data) into extra.
        """
        if request.method != "POST":
            raise OAuth2Exception(
                error="invalid_request",
                error_description="Apple callback must be POST (response_mode=form_post)",
            )

        form_data = await request.get_form_data()
        return CallbackData(
            code=form_data.form.get("code"),
            state=form_data.form.get("state"),
            error=form_data.form.get("error"),
            extra={"user_json": form_data.form.get("user")},
        )

    def get_user_info(
        self,
        token_response: TokenResponse,
        context: "Context",
        extra: dict[str, Any] | None = None,
    ) -> UserInfo:
        """Extract user info from Apple's id_token.

        Apple doesn't have a userinfo endpoint - all data is in the id_token.
        First-time user data (name) comes from the callback's `user` field.
        """
        id_token = getattr(token_response, "id_token", None)
        if not id_token:
            raise OAuth2Exception(
                error="server_error",
                error_description="No id_token in Apple token response",
            )

        # Validate id_token and extract claims
        id_token_payload = self.validate_id_token(id_token, context.secondary_storage)

        # Parse first-time user data if present
        first_time_user_data: AppleFirstTimeUserData | None = None
        if extra and (user_json := extra.get("user_json")):
            try:
                user_dict = json.loads(user_json)
                first_time_user_data = AppleFirstTimeUserData.model_validate(user_dict)
            except (json.JSONDecodeError, ValidationError) as e:
                logger.warning(f"Failed to parse Apple user data: {e}")

        return self.extract_user_info(id_token_payload, first_time_user_data)

    def parse_token_response(
        self, response: httpx.Response
    ) -> OAuth2TokenEndpointResponse:
        """Parse Apple's token response which includes id_token.

        Raises:
            OAuth2Exception: If the response cannot be parsed.
        """
        try:
            return OAuth2TokenEndpointResponse.model_validate_json(response.text)
        except (ValidationError, json.JSONDecodeError) as e:
            logger.error(f"Failed to parse Apple token response: {e}")
            raise OAuth2Exception(
                error="server_error",
                error_description="Failed to parse token response",
            )
