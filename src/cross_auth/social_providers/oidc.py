import json
import logging
import time
from typing import TYPE_CHECKING, Any, ClassVar

import httpx
import jwt
from jwt.algorithms import RSAAlgorithm

from cross_auth._context import Context
from cross_auth.models.oauth_token_response import TokenResponse

from .oauth import OAuth2Exception, OAuth2Provider, UserInfo

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

    from cross_auth._storage import SecondaryStorage

logger = logging.getLogger(__name__)


class OIDCProvider(OAuth2Provider):
    """Base class for OpenID Connect providers.

    OIDC providers return an id_token (JWT) containing user claims,
    which can be validated against the provider's JWKS endpoint.

    Subclasses should set:
        - jwks_uri: URL to fetch public keys
        - issuer: Expected 'iss' claim value (for validation)
        - jwks_cache_key: Key prefix for caching JWKS in secondary storage

    And optionally override:
        - extract_user_info_from_claims(): Custom claim-to-UserInfo mapping
    """

    jwks_uri: ClassVar[str]
    issuer: ClassVar[str]
    jwks_cache_key: ClassVar[str]

    # OIDC providers typically don't need a userinfo endpoint
    user_info_endpoint: ClassVar[str | None] = None

    _JWKS_REFETCH_COOLDOWN: ClassVar[int] = 60  # seconds

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._jwks_last_fetch_time: float = 0.0

    def _fetch_jwks(self, secondary_storage: "SecondaryStorage") -> dict[str, Any]:
        """Fetch provider's JWKS, using secondary_storage as cache."""
        if cached := secondary_storage.get(self.jwks_cache_key):
            return json.loads(cached)

        response = httpx.get(self.jwks_uri)
        response.raise_for_status()

        jwks = response.json()

        secondary_storage.set(self.jwks_cache_key, json.dumps(jwks), ttl=86400)
        self._jwks_last_fetch_time = time.monotonic()
        return jwks

    @staticmethod
    def _find_key_by_kid(keys: dict[str, Any], kid: str) -> "RSAPublicKey | None":
        """Find a public key by key ID in a JWKS dict."""
        for key in keys.get("keys", []):
            if key.get("kid") == kid:
                return RSAAlgorithm.from_jwk(key)  # type: ignore[return-value]
        return None

    def _get_public_key(
        self, kid: str, secondary_storage: "SecondaryStorage"
    ) -> "RSAPublicKey":
        """Get a specific public key by key ID from provider's JWKS."""
        keys = self._fetch_jwks(secondary_storage)
        if found := self._find_key_by_kid(keys, kid):
            return found

        # Key not found - clear cache and try again (handle key rotation)
        # Rate-limit refetches to prevent abuse
        elapsed = time.monotonic() - self._jwks_last_fetch_time
        if elapsed < self._JWKS_REFETCH_COOLDOWN:
            raise ValueError(
                f"Key {kid} not found in provider's JWKS "
                f"(retry available in {int(self._JWKS_REFETCH_COOLDOWN - elapsed)}s)"
            )

        secondary_storage.delete(self.jwks_cache_key)
        keys = self._fetch_jwks(secondary_storage)
        if found := self._find_key_by_kid(keys, kid):
            return found

        raise ValueError(f"Key {kid} not found in provider's JWKS")

    def validate_id_token(
        self, id_token: str, secondary_storage: "SecondaryStorage"
    ) -> dict[str, Any]:
        """Validate id_token JWT and return claims.

        Validates:
        - Signature against provider's public keys (JWKS)
        - Issuer matches expected issuer
        - Audience matches our client_id
        - Token is not expired
        """
        # Decode header to get key ID
        unverified_header = jwt.get_unverified_header(id_token)
        kid = unverified_header.get("kid")

        if not kid:
            raise OAuth2Exception(
                error="invalid_token",
                error_description="id_token missing kid header",
            )

        try:
            public_key = self._get_public_key(kid, secondary_storage)
        except ValueError as e:
            raise OAuth2Exception(
                error="invalid_token",
                error_description=str(e),
            ) from e

        try:
            return jwt.decode(
                id_token,
                public_key,
                algorithms=["RS256"],
                audience=self.client_id,
                issuer=self.issuer,
            )
        except jwt.ExpiredSignatureError as e:
            raise OAuth2Exception(
                error="invalid_token",
                error_description="id_token has expired",
            ) from e
        except jwt.InvalidAudienceError as e:
            raise OAuth2Exception(
                error="invalid_token",
                error_description="id_token audience mismatch",
            ) from e
        except jwt.InvalidIssuerError as e:
            raise OAuth2Exception(
                error="invalid_token",
                error_description="id_token issuer mismatch",
            ) from e
        except jwt.PyJWTError as e:
            raise OAuth2Exception(
                error="invalid_token",
                error_description=f"id_token validation failed: {e}",
            ) from e

    def extract_user_info_from_claims(
        self,
        claims: dict[str, Any],
        extra: dict[str, Any] | None = None,
    ) -> UserInfo:
        """Extract UserInfo from id_token claims.

        Override for provider-specific claim mapping.
        Default maps standard OIDC claims: sub -> id, email -> email

        Args:
            claims: Validated id_token claims.
            extra: Optional provider-specific data from callback (e.g., Apple's user field).
        """
        return {
            "id": claims["sub"],
            "email": claims.get("email"),
            "email_verified": claims.get("email_verified"),
        }

    def get_user_info(
        self,
        token_response: TokenResponse,
        context: Context,
        extra: dict[str, Any] | None = None,
    ) -> UserInfo:
        """Extract user info from id_token.

        OIDC providers return user info in the id_token JWT,
        so we don't need to call a userinfo endpoint.
        """
        id_token = getattr(token_response, "id_token", None)
        if not id_token:
            raise OAuth2Exception(
                error="server_error",
                error_description="No id_token in token response",
            )

        claims = self.validate_id_token(id_token, context.secondary_storage)
        return self.extract_user_info_from_claims(claims, extra)
