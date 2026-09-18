import json
import logging
import math
import re
import secrets
import time
from typing import TYPE_CHECKING, Any, ClassVar, cast

import httpx
import jwt
from cross_web import HTTPRequest
from jwt.algorithms import RSAAlgorithm

from cross_auth._context import Context
from cross_auth.models.oauth_token_response import TokenResponse

from .oauth import OAuth2Exception, OAuth2Provider, UserInfo

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

    from cross_auth._auth_flow import AuthRequest, LinkCodeData
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
    issuer: ClassVar[str | list[str]]
    jwks_cache_key: ClassVar[str]

    # OIDC providers typically don't need a userinfo endpoint
    user_info_endpoint: ClassVar[str | None] = None

    _JWKS_REFETCH_COOLDOWN: ClassVar[int] = 60  # seconds
    _JWKS_TTL_FLOOR: ClassVar[int] = 300  # 5 minutes
    _JWKS_TTL_CEILING: ClassVar[int] = 86400  # 24 hours
    _JWKS_TTL_FALLBACK: ClassVar[int] = 3600  # 1 hour when no Cache-Control

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        if self.extra_authorization_params:
            # Browser nonces belong to individual attempts, never configuration.
            self.extra_authorization_params = {
                key: value
                for key, value in self.extra_authorization_params.items()
                if key != "nonce"
            }
        self._jwks_last_fetch_time: float = 0.0

    def get_authorization_data(self) -> dict[str, str]:
        return {"nonce": secrets.token_urlsafe(32)}

    def build_authorization_params(
        self,
        state: str,
        redirect_uri: str,
        *,
        request: HTTPRequest | None = None,
        code_challenge: str | None = None,
        code_challenge_method: str | None = None,
        login_hint: str | None = None,
        provider_data: dict[str, str] | None = None,
    ) -> dict[str, str]:
        params = super().build_authorization_params(
            state,
            redirect_uri,
            request=request,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            login_hint=login_hint,
            provider_data=provider_data,
        )
        if provider_data is not None and "nonce" in provider_data:
            params["nonce"] = provider_data["nonce"]

        return params

    @classmethod
    def _ttl_from_cache_control(cls, header: str | None) -> int:
        """Extract max-age from a Cache-Control header, clamped to floor/ceiling.

        Returns the fallback TTL if the header is missing or has no max-age.
        """
        if not header:
            return cls._JWKS_TTL_FALLBACK

        match = re.search(r"max-age\s*=\s*(\d+)", header, re.IGNORECASE)
        if not match:
            return cls._JWKS_TTL_FALLBACK

        return max(cls._JWKS_TTL_FLOOR, min(int(match.group(1)), cls._JWKS_TTL_CEILING))

    def _fetch_jwks(self, secondary_storage: "SecondaryStorage") -> dict[str, Any]:
        """Fetch provider's JWKS, using secondary_storage as cache.

        TTL honors the JWKS response's Cache-Control max-age (clamped) so cache
        doesn't outlive the provider's key rotation window.
        """
        if cached := secondary_storage.get(self.jwks_cache_key):
            return json.loads(cached)

        response = httpx.get(self.jwks_uri)
        response.raise_for_status()

        jwks = response.json()
        ttl = self._ttl_from_cache_control(response.headers.get("cache-control"))

        secondary_storage.set(self.jwks_cache_key, json.dumps(jwks), ttl=ttl)
        self._jwks_last_fetch_time = time.monotonic()
        return jwks

    @staticmethod
    def _find_key_by_kid(keys: dict[str, Any], kid: str) -> "RSAPublicKey | None":
        """Find a public key by key ID in a JWKS dict."""
        for key in keys.get("keys", []):
            if key.get("kid") == kid:
                return cast("RSAPublicKey", RSAAlgorithm.from_jwk(key))
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
        - Required OIDC claims and their types
        - Token is not expired or issued in the future
        """
        try:
            unverified_header = jwt.get_unverified_header(id_token)
            kid = unverified_header.get("kid")
            if not isinstance(kid, str) or not kid:
                raise OAuth2Exception(
                    error="invalid_token",
                    error_description="id_token missing or invalid kid header",
                )

            try:
                public_key = self._get_public_key(kid, secondary_storage)
            except ValueError as error:
                raise OAuth2Exception(
                    error="invalid_token",
                    error_description=str(error),
                ) from error

            claims = jwt.decode(
                id_token,
                public_key,
                algorithms=["RS256"],
                audience=self.client_id,
                issuer=self.issuer,
                options={"require": ["iss", "sub", "aud", "exp", "iat"]},
            )
            if not isinstance(claims["iss"], str):
                raise jwt.InvalidIssuerError("Issuer must be a string")
            if not isinstance(claims["sub"], str) or not claims["sub"]:
                raise jwt.InvalidTokenError("Subject must be a nonempty string")

            # PyJWT coerces numeric strings and booleans. OIDC timestamps must
            # be JSON numbers, including fractional seconds allowed by JWT.
            for field in ("exp", "iat", "nbf"):
                if field not in claims:
                    continue
                value = claims[field]
                if (
                    isinstance(value, bool)
                    or not isinstance(value, (int, float))
                    or (isinstance(value, float) and not math.isfinite(value))
                ):
                    raise jwt.InvalidTokenError(f"{field} must be a finite number")

            return claims
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
        except (jwt.PyJWTError, TypeError, OverflowError, UnicodeError) as e:
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

    def validate_auth_request(self, auth_request: "AuthRequest") -> None:
        if not auth_request.provider_data.get("nonce"):
            raise OAuth2Exception(
                error="invalid_request",
                error_description="Missing provider nonce; restart authorization",
            )

    def validate_link_data(self, link_data: "LinkCodeData") -> None:
        if not link_data.provider_data.get("nonce"):
            raise OAuth2Exception(
                error="invalid_request",
                error_description="Missing provider nonce; restart linking",
            )

    def fetch_user_info(
        self,
        token_response: TokenResponse,
        context: Context,
        extra: dict[str, Any] | None = None,
        *,
        provider_data: dict[str, str] | None = None,
    ) -> UserInfo:
        """Extract user info from id_token.

        OIDC providers return user info in the id_token JWT,
        so we don't need to call a userinfo endpoint. Browser flows supply the
        stored nonce, which must match the signed claim exactly.
        """
        id_token = token_response.id_token
        if not id_token:
            raise OAuth2Exception(
                error="server_error",
                error_description="No id_token in token response",
            )

        claims = self.validate_id_token(id_token, context.secondary_storage)
        nonce = provider_data.get("nonce") if provider_data is not None else None
        if provider_data is not None and (
            not isinstance(nonce, str)
            or not nonce
            or not isinstance(claims.get("nonce"), str)
            or claims["nonce"] != nonce
        ):
            raise OAuth2Exception(
                error="invalid_token",
                error_description="id_token nonce mismatch",
            )
        return self.extract_user_info_from_claims(claims, extra)
