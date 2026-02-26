import json
import logging
import time
from typing import Annotated, Any, Literal

import jwt
from cross_web import AsyncHTTPRequest
from pydantic import BaseModel, BeforeValidator, EmailStr

from .oauth import (
    CallbackData,
    OAuth2Exception,
    TokenExchangeParams,
    UserInfo,
)
from .oidc import OIDCProvider

logger = logging.getLogger(__name__)

_REAL_USER_STATUS_MAP: dict[int, Literal["unsupported", "unknown", "likely_real"]] = {
    0: "unsupported",
    1: "unknown",
    2: "likely_real",
}


def _parse_apple_bool_string(v: str | bool | None) -> bool:
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


def _parse_real_user_status(
    v: int | str | None,
) -> Literal["unsupported", "unknown", "likely_real"] | None:
    """Convert Apple's integer real_user_status to descriptive string.

    Apple sends: 0=unsupported, 1=unknown, 2=likely_real
    """

    if v is None:
        return None

    if isinstance(v, str):
        return v  # type: ignore  # Already a string, assume valid

    if (result := _REAL_USER_STATUS_MAP.get(v)) is None:
        raise ValueError(f"Invalid real_user_status value: {v}")

    return result


class AppleIdTokenPayload(BaseModel):
    iss: Literal["https://appleid.apple.com"]
    sub: str
    aud: str
    iat: int
    exp: int
    email: EmailStr | None = None
    email_verified: Annotated[bool, BeforeValidator(_parse_apple_bool_string)] = False
    is_private_email: Annotated[bool, BeforeValidator(_parse_apple_bool_string)] = False
    auth_time: int | None = None
    nonce: str | None = None
    nonce_supported: bool | None = None
    real_user_status: Annotated[
        Literal["unsupported", "unknown", "likely_real"] | None,
        BeforeValidator(_parse_real_user_status),
    ] = None
    # transfer_sub is only present during the 60-day window after an app is
    # transferred between developer teams. It maps users from old to new team.
    # We parse it but don't handle migration - implement if you need app transfers.
    # See: https://developer.apple.com/documentation/technotes/tn3159
    transfer_sub: str | None = None


class AppleProvider(OIDCProvider):
    """Apple Sign In OAuth2 Provider.

    Key differences from standard OAuth:
    - client_secret is a JWT signed with your private key (ES256)
    - No userinfo endpoint - all data in id_token
    - Email is always in the id_token (when email scope is requested)
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

    def __init__(
        self,
        client_id: str,
        *,
        team_id: str,
        key_id: str,
        private_key: str,
    ):
        self.team_id = team_id
        self.key_id = key_id
        self.private_key = private_key
        super().__init__(client_id=client_id)

    def generate_client_secret(self) -> str:
        """Generate a JWT client secret for Apple.

        Apple requires client_secret to be a JWT signed with ES256.
        Generated fresh on each token exchange, so we use a short expiry.
        """
        now = int(time.time())

        payload = {
            "iss": self.team_id,
            "iat": now,
            "exp": now + 300,  # 5 minutes
            "aud": "https://appleid.apple.com",
            "sub": self.client_id,
        }

        return jwt.encode(
            payload,
            self.private_key,
            algorithm="ES256",
            headers={"kid": self.key_id, "alg": "ES256"},
        )

    def build_authorization_params(
        self,
        state: str,
        proxy_redirect_uri: str,
        response_type: str,
        code_challenge: str | None = None,
        code_challenge_method: str | None = None,
        login_hint: str | None = None,
        scope_override: str | None = None,
    ) -> dict:
        """Build authorization request parameters for Apple.

        IMPORTANT: scope must be space-separated ("name email"), NOT plus-encoded.
        """
        params = {
            "client_id": self.client_id,
            "redirect_uri": proxy_redirect_uri,
            "response_type": "code",
            "scope": scope_override if scope_override is not None else "name email",
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
            "client_id": self.client_id,
            "client_secret": self.generate_client_secret(),
        }

        if code_verifier:
            params["code_verifier"] = code_verifier

        return params

    def extract_user_info_from_claims(
        self,
        claims: dict[str, Any],
        extra: dict[str, Any] | None = None,
    ) -> UserInfo:
        """Extract user info from Apple's id_token claims.

        Email is always present in the id_token (when email scope is requested).
        The user's name is only available via the `extra` dict on first authorization.
        """
        id_token_payload = AppleIdTokenPayload.model_validate(claims)

        info: UserInfo = {
            "id": id_token_payload.sub,
            "email": id_token_payload.email,
            "email_verified": id_token_payload.email_verified,
        }

        if extra and (user := extra.get("user")):
            name = user.get("name", {})
            full_name = (
                f"{name.get('firstName', '')} {name.get('lastName', '')}".strip()
            )
            if full_name:
                info["name"] = full_name

        return info

    async def extract_callback_data(self, request: AsyncHTTPRequest) -> CallbackData:
        """Extract callback data from Apple's POST form data.

        Apple uses response_mode=form_post, so callback data comes via POST.
        """
        if request.method != "POST":
            raise OAuth2Exception(
                error="invalid_request",
                error_description="Apple callback must be POST (response_mode=form_post)",
            )

        form_data = await request.get_form_data()

        extra: dict[str, Any] = {}
        if user_json := form_data.form.get("user"):
            try:
                extra["user"] = json.loads(user_json)
            except json.JSONDecodeError:
                logger.warning("Failed to parse Apple user JSON: %s", user_json)

        return CallbackData(
            code=form_data.form.get("code"),
            state=form_data.form.get("state"),
            error=form_data.form.get("error"),
            extra=extra if extra else None,
        )
