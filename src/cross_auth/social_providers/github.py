from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, cast

import httpx
from pydantic import AnyUrl, BaseModel, EmailStr, Field

from .oauth import OAuth2Provider, UserInfo

logger = logging.getLogger(__name__)


class GitHubPlan(BaseModel):
    collaborators: int
    name: str
    space: int
    private_repos: int


class GitHubUser(BaseModel):
    login: str = Field(examples=["octocat"])
    id: int = Field(examples=[1])
    user_view_type: str | None = None
    node_id: str = Field(examples=["MDQ6VXNlcjE="])
    avatar_url: AnyUrl = Field(
        ..., examples=["https://github.com/images/error/octocat_happy.gif"]
    )
    gravatar_id: str | None = Field(examples=["41d064eb2195891e12d0413f63227ea7"])
    url: AnyUrl = Field(examples=["https://api.github.com/users/octocat"])
    html_url: AnyUrl = Field(examples=["https://github.com/octocat"])
    followers_url: AnyUrl = Field(
        ..., examples=["https://api.github.com/users/octocat/followers"]
    )
    following_url: str = Field(
        ..., examples=["https://api.github.com/users/octocat/following{/other_user}"]
    )
    gists_url: str = Field(
        ..., examples=["https://api.github.com/users/octocat/gists{/gist_id}"]
    )
    starred_url: str = Field(
        ..., examples=["https://api.github.com/users/octocat/starred{/owner}{/repo}"]
    )
    subscriptions_url: AnyUrl = Field(
        ..., examples=["https://api.github.com/users/octocat/subscriptions"]
    )
    organizations_url: AnyUrl = Field(
        ..., examples=["https://api.github.com/users/octocat/orgs"]
    )
    repos_url: AnyUrl = Field(
        ..., examples=["https://api.github.com/users/octocat/repos"]
    )
    events_url: str = Field(
        ..., examples=["https://api.github.com/users/octocat/events{/privacy}"]
    )
    received_events_url: AnyUrl = Field(
        ..., examples=["https://api.github.com/users/octocat/received_events"]
    )
    type: str = Field(examples=["User"])
    site_admin: bool
    name: str | None = Field(examples=["monalisa octocat"])
    company: str | None = Field(examples=["GitHub"])
    blog: str | None = Field(examples=["https://github.com/blog"])
    location: str | None = Field(examples=["San Francisco"])
    email: EmailStr | None = Field(examples=["octocat@github.com"])
    notification_email: EmailStr | None = Field(
        default=None, examples=["octocat@github.com"]
    )
    hireable: bool | None
    bio: str | None = Field(examples=["There once was..."])
    twitter_username: str | None = Field(default=None, examples=["monalisa"])
    public_repos: int = Field(examples=[2])
    public_gists: int = Field(examples=[1])
    followers: int = Field(examples=[20])
    following: int = Field(examples=[0])
    created_at: datetime = Field(examples=["2008-01-14T04:33:35Z"])
    updated_at: datetime = Field(examples=["2008-01-14T04:33:35Z"])

    plan: GitHubPlan | None = None
    business_plus: bool | None = None
    ldap_dn: str | None = None


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
        """
        super().__init__(client_id, client_secret, trust_email)

        if authorization_endpoint is not None:
            self.authorization_endpoint = authorization_endpoint
        if token_endpoint is not None:
            self.token_endpoint = token_endpoint
        if api_base_url is not None:
            api_base_url = api_base_url.rstrip("/")
            self.user_info_endpoint = f"{api_base_url}/user"
            self.emails_endpoint = f"{api_base_url}/user/emails"

    def fetch_user_info(self, access_token: str) -> UserInfo:
        # Cast to dict[str, Any] since GitHub API returns more fields than UserInfo
        info = cast(dict[str, Any], super().fetch_user_info(access_token))

        try:
            response = httpx.get(
                self.emails_endpoint,
                headers={"Authorization": f"Bearer {access_token}"},
            )

            response.raise_for_status()

            emails = response.json()

            # Always use the primary email
            primary = next((e for e in emails if e["primary"]), None)

            if primary:
                info["email"] = primary["email"]
                info["email_verified"] = primary["verified"]
            else:
                info["email"] = None
                info["email_verified"] = None

        except Exception as e:
            logger.error(f"Failed to fetch user emails: {e}")
            info["email"] = None
            info["email_verified"] = None

        # Ensure name is always a string, falling back to login (username)
        if not info.get("name"):
            info["name"] = info["login"]

        return cast(UserInfo, info)
