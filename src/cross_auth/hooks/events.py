from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from cross_web import AsyncHTTPRequest, Cookie, Response

    from .._auth_flow import AuthRequest, InitiateLinkRequest, LinkCodeData
    from .._issuer import (
        AuthorizationCodeGrantData,
        AuthorizationCodeGrantRequest,
        PasswordGrantRequest,
    )
    from .._session import SessionData
    from .._storage import SocialAccount, User
    from ..models.oauth_token_response import TokenResponse
    from ..social_providers.oauth import (
        CallbackData,
        OAuth2Provider,
        UserInfo,
        ValidatedUserInfo,
    )


@dataclass(frozen=True, slots=True)
class BeforeAuthenticateEvent:
    email: str
    password: str


@dataclass(frozen=True, slots=True)
class AfterAuthenticateEvent:
    email: str
    user: User | None


@dataclass(frozen=True, slots=True)
class BeforeLoginEvent:
    user_id: str
    response: Response


@dataclass(frozen=True, slots=True)
class AfterLoginEvent:
    user_id: str
    response: Response
    session_id: str
    session_data: SessionData
    cookie: Cookie


@dataclass(frozen=True, slots=True)
class BeforeLogoutEvent:
    request: AsyncHTTPRequest
    response: Response
    session_id: str | None


@dataclass(frozen=True, slots=True)
class AfterLogoutEvent:
    request: AsyncHTTPRequest
    response: Response
    session_id: str | None


@dataclass(frozen=True, slots=True)
class BeforeOAuthAuthorizeEvent:
    provider: OAuth2Provider
    request: AsyncHTTPRequest
    login_hint: str | None


@dataclass(frozen=True, slots=True)
class AfterOAuthAuthorizeEvent:
    provider: OAuth2Provider
    request: AsyncHTTPRequest
    redirect_uri: str
    client_id: str
    client_state: str | None
    login_hint: str | None
    code_challenge: str
    code_challenge_method: Literal["S256"]
    state: str
    authorization_url: str


@dataclass(frozen=True, slots=True)
class BeforeOAuthCallbackEvent:
    provider: OAuth2Provider
    request: AsyncHTTPRequest
    user_info: UserInfo
    validated_user_info: ValidatedUserInfo


@dataclass(frozen=True, slots=True)
class AfterOAuthCallbackEvent:
    provider: OAuth2Provider
    request: AsyncHTTPRequest
    auth_request: AuthRequest
    callback_data: CallbackData
    token_response: TokenResponse
    user_info: UserInfo
    validated_user_info: ValidatedUserInfo
    user: User
    social_account: SocialAccount
    created_user: User | None
    created_social_account: SocialAccount | None
    authorization_code: str | None
    redirect_uri: str | None
    client_state: str | None


@dataclass(frozen=True, slots=True)
class BeforeOAuthLinkEvent:
    provider: OAuth2Provider
    request: AsyncHTTPRequest
    user: User


@dataclass(frozen=True, slots=True)
class AfterOAuthLinkEvent:
    provider: OAuth2Provider
    request: AsyncHTTPRequest
    user: User
    link_request: InitiateLinkRequest
    state: str
    authorization_url: str


@dataclass(frozen=True, slots=True)
class BeforeOAuthFinalizeLinkEvent:
    provider: OAuth2Provider
    request: AsyncHTTPRequest
    user: User
    allow_login: bool
    user_info: UserInfo
    validated_user_info: ValidatedUserInfo


@dataclass(frozen=True, slots=True)
class AfterOAuthFinalizeLinkEvent:
    provider: OAuth2Provider
    request: AsyncHTTPRequest
    user: User
    link_data: LinkCodeData
    allow_login: bool
    token_response: TokenResponse
    user_info: UserInfo
    validated_user_info: ValidatedUserInfo
    social_account: SocialAccount
    created_social_account: SocialAccount | None


@dataclass(frozen=True, slots=True)
class BeforeOAuthDisconnectEvent:
    provider: OAuth2Provider
    request: AsyncHTTPRequest
    user: User
    social_account: SocialAccount


@dataclass(frozen=True, slots=True)
class AfterOAuthDisconnectEvent:
    provider: OAuth2Provider
    request: AsyncHTTPRequest
    user: User
    social_account: SocialAccount


@dataclass(frozen=True, slots=True)
class BeforeTokenPasswordEvent:
    client_id: str
    username: str
    user: User | None
    scope: str | None


@dataclass(frozen=True, slots=True)
class AfterTokenPasswordEvent:
    request: PasswordGrantRequest
    client_id: str
    username: str
    user: User
    token_response: TokenResponse


@dataclass(frozen=True, slots=True)
class BeforeTokenAuthorizationCodeEvent:
    client_id: str
    user_id: str
    scope: str | None


@dataclass(frozen=True, slots=True)
class AfterTokenAuthorizationCodeEvent:
    request: AuthorizationCodeGrantRequest
    code: str
    authorization_data: AuthorizationCodeGrantData
    token_response: TokenResponse


__all__ = [
    "AfterAuthenticateEvent",
    "AfterLoginEvent",
    "AfterLogoutEvent",
    "AfterOAuthAuthorizeEvent",
    "AfterOAuthCallbackEvent",
    "AfterOAuthDisconnectEvent",
    "AfterOAuthFinalizeLinkEvent",
    "AfterOAuthLinkEvent",
    "AfterTokenAuthorizationCodeEvent",
    "AfterTokenPasswordEvent",
    "BeforeAuthenticateEvent",
    "BeforeLoginEvent",
    "BeforeLogoutEvent",
    "BeforeOAuthAuthorizeEvent",
    "BeforeOAuthCallbackEvent",
    "BeforeOAuthDisconnectEvent",
    "BeforeOAuthFinalizeLinkEvent",
    "BeforeOAuthLinkEvent",
    "BeforeTokenAuthorizationCodeEvent",
    "BeforeTokenPasswordEvent",
]
