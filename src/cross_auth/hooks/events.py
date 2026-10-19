from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from cross_web import HTTPRequest, Response

    from .._auth_flow import AuthRequest, InitiateLinkRequest, LinkCodeData
    from .._issuer import (
        AuthorizationCodeGrantData,
        AuthorizationCodeGrantRequest,
        PasswordGrantRequest,
    )
    from .._session import SessionMetadata
    from .._storage import SessionRecord
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


LoginCredential = Literal["cookie", "bearer"]


@dataclass(frozen=True, slots=True)
class BeforeLoginEvent:
    """A login that is about to issue a credential.

    ``user_id`` is the verified identity being logged in; hooks may deny the
    login by raising but cannot change who is logged in. ``max_age`` and
    ``metadata`` describe the Cross Auth session that will be created and may
    be adjusted; both are ``None`` when an application ``token_issuer`` mints
    the credential. ``response`` is the HTTP response of a cookie login and
    ``None`` for bearer logins.
    """

    user_id: str
    credential: LoginCredential
    max_age: int | None
    metadata: SessionMetadata | None
    response: Response | None = None


@dataclass(frozen=True, slots=True)
class AfterLoginEvent:
    # The raw token is deliberately not exposed to hooks. ``session_record`` is
    # ``None`` when an application ``token_issuer`` minted the credential.
    user_id: str
    credential: LoginCredential
    session_record: SessionRecord | None
    response: Response | None = None


@dataclass(frozen=True, slots=True)
class BeforeOAuthIdTokenEvent:
    provider: str
    id_token: str
    user_info: dict[str, Any] | None


@dataclass(frozen=True, slots=True)
class AfterOAuthIdTokenEvent:
    provider: str
    user: User
    created: bool
    social_account: SocialAccount


@dataclass(frozen=True, slots=True)
class BeforeUserCreateEvent:
    """A user about to be created.

    ``email`` is already canonicalized by ``normalize_email``. ``email`` and
    ``email_verified`` are read-only; hooks may adjust ``extra_fields``.
    """

    user_info: dict[str, Any]
    email: str
    email_verified: bool
    extra_fields: dict[str, Any]


@dataclass(frozen=True, slots=True)
class AfterUserCreateEvent:
    user_info: dict[str, Any]
    user: User


@dataclass(frozen=True, slots=True)
class BeforeSocialAccountCreateEvent:
    user_id: Any
    provider: str
    provider_user_id: str
    access_token: str | None
    refresh_token: str | None
    access_token_expires_at: datetime | None
    refresh_token_expires_at: datetime | None
    scope: str | None
    user_info: dict[str, Any]
    provider_email: str | None
    provider_email_verified: bool | None
    is_login_method: bool
    extra_fields: dict[str, Any]
    operation: Literal["create"] = field(init=False, default="create")


@dataclass(frozen=True, slots=True)
class AfterSocialAccountCreateEvent:
    user_info: dict[str, Any]
    social_account: SocialAccount
    operation: Literal["create"] = field(init=False, default="create")


@dataclass(frozen=True, slots=True)
class BeforeSocialAccountUpdateEvent:
    social_account: SocialAccount
    user_id: Any
    provider: str
    provider_user_id: str
    access_token: str | None
    refresh_token: str | None
    access_token_expires_at: datetime | None
    refresh_token_expires_at: datetime | None
    scope: str | None
    user_info: dict[str, Any]
    provider_email: str | None
    provider_email_verified: bool | None
    is_login_method: bool
    extra_fields: dict[str, Any]
    operation: Literal["update"] = field(init=False, default="update")


@dataclass(frozen=True, slots=True)
class AfterSocialAccountUpdateEvent:
    user_info: dict[str, Any]
    social_account: SocialAccount
    operation: Literal["update"] = field(init=False, default="update")


@dataclass(frozen=True, slots=True)
class BeforeLogoutEvent:
    request: HTTPRequest
    response: Response
    session_record: SessionRecord | None


@dataclass(frozen=True, slots=True)
class AfterLogoutEvent:
    request: HTTPRequest
    response: Response
    session_record: SessionRecord | None


@dataclass(frozen=True, slots=True)
class BeforeOAuthAuthorizeEvent:
    provider: OAuth2Provider
    request: HTTPRequest
    login_hint: str | None


@dataclass(frozen=True, slots=True)
class AfterOAuthAuthorizeEvent:
    provider: OAuth2Provider
    request: HTTPRequest
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
    """Provider data about to sign a user in.

    ``validated_user_info`` holds the verified claims that select, auto-link or
    create the account; hooks may read them but not change them. ``user_info``
    is profile metadata and may be adjusted.
    """

    provider: OAuth2Provider
    request: HTTPRequest
    user_info: UserInfo
    validated_user_info: ValidatedUserInfo


@dataclass(frozen=True, slots=True)
class AfterOAuthCallbackEvent:
    provider: OAuth2Provider
    request: HTTPRequest
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
    request: HTTPRequest
    user: User


@dataclass(frozen=True, slots=True)
class AfterOAuthLinkEvent:
    provider: OAuth2Provider
    request: HTTPRequest
    user: User
    link_request: InitiateLinkRequest
    state: str
    authorization_url: str


@dataclass(frozen=True, slots=True)
class BeforeOAuthFinalizeLinkEvent:
    """Provider data about to be linked to the signed-in ``user``.

    ``user`` and the verified ``validated_user_info`` claims are read-only;
    ``allow_login`` and the ``user_info`` profile metadata may be adjusted.
    """

    provider: OAuth2Provider
    request: HTTPRequest
    user: User
    allow_login: bool
    user_info: UserInfo
    validated_user_info: ValidatedUserInfo


@dataclass(frozen=True, slots=True)
class AfterOAuthFinalizeLinkEvent:
    provider: OAuth2Provider
    request: HTTPRequest
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
    request: HTTPRequest
    user: User
    social_account: SocialAccount


@dataclass(frozen=True, slots=True)
class AfterOAuthDisconnectEvent:
    provider: OAuth2Provider
    request: HTTPRequest
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
    "AfterOAuthIdTokenEvent",
    "AfterOAuthLinkEvent",
    "AfterSocialAccountCreateEvent",
    "AfterSocialAccountUpdateEvent",
    "AfterTokenAuthorizationCodeEvent",
    "AfterTokenPasswordEvent",
    "AfterUserCreateEvent",
    "BeforeAuthenticateEvent",
    "BeforeLoginEvent",
    "BeforeLogoutEvent",
    "BeforeOAuthAuthorizeEvent",
    "BeforeOAuthCallbackEvent",
    "BeforeOAuthDisconnectEvent",
    "BeforeOAuthFinalizeLinkEvent",
    "BeforeOAuthIdTokenEvent",
    "BeforeOAuthLinkEvent",
    "BeforeSocialAccountCreateEvent",
    "BeforeSocialAccountUpdateEvent",
    "BeforeTokenAuthorizationCodeEvent",
    "BeforeTokenPasswordEvent",
    "BeforeUserCreateEvent",
    "LoginCredential",
]
