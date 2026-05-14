from __future__ import annotations

from typing import Any

from .oauth import UserInfo
from .oidc import OIDCProvider


class GoogleProvider(OIDCProvider):
    id = "google"

    authorization_endpoint = "https://accounts.google.com/o/oauth2/v2/auth"
    token_endpoint = "https://oauth2.googleapis.com/token"
    jwks_uri = "https://www.googleapis.com/oauth2/v3/certs"
    # Google emits id_tokens with either form of iss; both must validate.
    # https://developers.google.com/identity/gsi/web/guides/verify-google-id-token
    issuer = ["https://accounts.google.com", "accounts.google.com"]
    jwks_cache_key = "google:jwks"

    scopes = ["openid", "email", "profile"]
    supports_pkce = True

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        trust_email: bool = False,
        *,
        extra_authorization_params: dict[str, str] | None = None,
        authorization_endpoint: str | None = None,
        token_endpoint: str | None = None,
        jwks_uri: str | None = None,
    ):
        """
        Initialize the Google OAuth2 / OIDC provider.

        Args:
            client_id: OAuth2 client ID.
            client_secret: OAuth2 client secret.
            trust_email: If True, emails from this provider are trusted for account
                linking even without explicit email_verified=True. Defaults to False
                because Google provides an email_verified claim.
            extra_authorization_params: Additional query parameters for the
                authorization URL. Common Google-specific values:
                ``{"access_type": "offline", "prompt": "consent"}`` to receive a
                refresh token, ``{"hd": "example.com"}`` to hint a Workspace
                domain, ``{"include_granted_scopes": "true"}`` for incremental
                authorization.
            authorization_endpoint: Custom authorization URL (for browser redirects).
            token_endpoint: Custom token exchange URL (for server-to-server calls).
            jwks_uri: Custom JWKS URL (for server-to-server ID token validation).
        """
        super().__init__(
            client_id,
            client_secret,
            trust_email,
            extra_authorization_params=extra_authorization_params,
        )

        if authorization_endpoint is not None:
            self.authorization_endpoint = authorization_endpoint
        if token_endpoint is not None:
            self.token_endpoint = token_endpoint
        if jwks_uri is not None:
            self.jwks_uri = jwks_uri

    def extract_user_info_from_claims(
        self,
        claims: dict[str, Any],
        extra: dict[str, Any] | None = None,
    ) -> UserInfo:
        info: UserInfo = {
            "id": claims["sub"],
            "email": claims.get("email"),
            "email_verified": claims.get("email_verified"),
        }
        if name := claims.get("name"):
            info["name"] = name
        return info
