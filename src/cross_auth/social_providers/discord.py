from __future__ import annotations

from typing import Any

from cross_auth._context import Context
from cross_auth.models.oauth_token_response import TokenResponse

from .oauth import OAuth2Provider, UserInfo


class DiscordProvider(OAuth2Provider):
    # NOTE: Discord users without an email will fail authentication
    # (email is required).
    id = "discord"
    authorization_endpoint = "https://discord.com/oauth2/authorize"
    token_endpoint = "https://discord.com/api/oauth2/token"
    user_info_endpoint = "https://discord.com/api/users/@me"
    scopes = ["identify", "email"]
    supports_pkce = True

    def fetch_user_info(
        self,
        token_response: TokenResponse,
        context: Context,
        extra: dict[str, Any] | None = None,
        *,
        provider_data: dict[str, str] | None = None,
    ) -> UserInfo:
        info = super().fetch_user_info(
            token_response, context, extra, provider_data=provider_data
        )

        # Map Discord's 'verified' field to our standard 'email_verified'
        info["email_verified"] = info.get("verified")

        return info
