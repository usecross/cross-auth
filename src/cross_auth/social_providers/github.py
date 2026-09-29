from __future__ import annotations

import logging
from typing import Any, cast

import httpx

from cross_auth._context import Context
from cross_auth.models.oauth_token_response import TokenResponse

from .oauth import DEFAULT_TOKEN_EXCHANGE_TIMEOUT, OAuth2Provider, UserInfo

logger = logging.getLogger(__name__)


class GitHubProvider(OAuth2Provider):
    id = "github"

    authorization_endpoint = "https://github.com/login/oauth/authorize"
    token_endpoint = "https://github.com/login/oauth/access_token"
    user_info_endpoint = "https://api.github.com/user"
    emails_endpoint = "https://api.github.com/user/emails"
    scopes = ["user:email"]
    supports_pkce = True

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        trust_email: bool = True,
        *,
        authorization_endpoint: str | None = None,
        token_endpoint: str | None = None,
        api_base_url: str | None = None,
        token_exchange_timeout: float | httpx.Timeout | None = (
            DEFAULT_TOKEN_EXCHANGE_TIMEOUT
        ),
    ):
        """
        Initialize the GitHub OAuth2 provider.

        Args:
            client_id: OAuth2 client ID.
            client_secret: OAuth2 client secret.
            trust_email: If True, emails from this provider are trusted for account
                linking even without explicit email_verified=True.
            authorization_endpoint: Custom authorization URL (for browser redirects).
            token_endpoint: Custom token exchange URL (for server-to-server calls).
            api_base_url: Custom API base URL for user info and emails
                (for server-to-server calls). Should not include trailing slash.
            token_exchange_timeout: Timeout for the provider token request. Set to
                None to disable it.
        """
        super().__init__(
            client_id,
            client_secret,
            trust_email,
            token_exchange_timeout=token_exchange_timeout,
        )

        if authorization_endpoint is not None:
            self.authorization_endpoint = authorization_endpoint
        if token_endpoint is not None:
            self.token_endpoint = token_endpoint
        if api_base_url is not None:
            api_base_url = api_base_url.rstrip("/")
            self.user_info_endpoint = f"{api_base_url}/user"
            self.emails_endpoint = f"{api_base_url}/user/emails"

    def fetch_user_info(
        self,
        token_response: TokenResponse,
        context: Context,
        extra: dict[str, Any] | None = None,
        *,
        provider_data: dict[str, str] | None = None,
    ) -> UserInfo:
        # Cast to dict[str, Any] since GitHub API returns more fields than UserInfo
        info = cast(
            dict[str, Any],
            super().fetch_user_info(
                token_response, context, extra, provider_data=provider_data
            ),
        )
        fallback_email = info.get("email")
        fallback_email_verified = info.get("email_verified")

        try:
            response = httpx.get(
                self.emails_endpoint,
                headers={"Authorization": f"Bearer {token_response.access_token}"},
            )

            response.raise_for_status()

            emails = response.json()

            # Always use the primary email
            primary = next((e for e in emails if e["primary"]), None)

            if primary:
                info["email"] = primary["email"]
                info["email_verified"] = primary["verified"]

        except httpx.HTTPStatusError as e:
            logger.error(
                "Failed to fetch user emails from %s: %s (status=%d, body=%s, scope=%s)",
                self.emails_endpoint,
                e,
                e.response.status_code,
                e.response.text,
                token_response.scope,
            )
        except Exception as e:
            logger.error(
                "Failed to fetch user emails from %s: %s (scope=%s)",
                self.emails_endpoint,
                e,
                token_response.scope,
            )

        info["email"] = info.get("email") or fallback_email
        info["email_verified"] = info.get("email_verified", fallback_email_verified)

        # Ensure name is always a string, falling back to login (username)
        if not info.get("name"):
            info["name"] = info["login"]

        return cast(UserInfo, info)
