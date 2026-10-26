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


# Before hooks receive these read-only views instead of the live provider and
# storage-backed records, so a hook cannot change an identity in place. They
# hold only immutable values; credentials and provider configuration stay out.


@dataclass(frozen=True, slots=True)
class ProviderSnapshot:
    """Read-only view of an OAuth provider given to before hooks."""

    id: str
    trust_email: bool

    @classmethod
    def of(cls, provider: OAuth2Provider) -> ProviderSnapshot:
        return cls(id=provider.id, trust_email=provider.trust_email)


@dataclass(frozen=True, slots=True)
class UserSnapshot:
    """Read-only view of a stored user given to before hooks."""

    id: Any
    email: str | None
    email_verified: bool

    @classmethod
    def of(cls, user: User) -> UserSnapshot:
        return cls(id=user.id, email=user.email, email_verified=user.email_verified)


@dataclass(frozen=True, slots=True)
class SocialAccountSnapshot:
    """Read-only view of a stored social account given to before hooks."""

    id: Any
    user_id: Any
    provider: str
    provider_user_id: str
    provider_email: str | None
    provider_email_verified: bool | None
    is_login_method: bool

    @classmethod
    def of(cls, social_account: SocialAccount) -> SocialAccountSnapshot:
        return cls(
            id=social_account.id,
            user_id=social_account.user_id,
            provider=social_account.provider,
            provider_user_id=social_account.provider_user_id,
            provider_email=social_account.provider_email,
            provider_email_verified=social_account.provider_email_verified,
            is_login_method=social_account.is_login_method,
        )


@dataclass(frozen=True, slots=True)
class BeforeAuthenticateEvent:
    email: str
    password: str


@dataclass(frozen=True, slots=True)
class AfterAuthenticateEvent:
    email: str
    user: User | None


# "django_session" is a native Django session started by django.contrib.auth.
LoginCredential = Literal["cookie", "bearer", "django_session"]
# "current" revokes the request's session; "all" every session of its user.
LogoutScope = Literal["current", "all"]


@dataclass(frozen=True, slots=True)
class BeforeLoginEvent:
    """A login that is about to issue a credential.

    ``user_id`` is the verified identity being logged in; hooks may deny the
    login by raising but cannot change who is logged in. ``max_age`` and
    ``metadata`` describe the Cross Auth session that will be created and may
    be adjusted; both are ``None`` when an application ``token_issuer`` or the
    web framework (``django_session``) creates the credential. ``response`` is
    the HTTP response of a browser login and ``None`` for bearer logins.
    """

    user_id: str
    credential: LoginCredential
    max_age: int | None
    metadata: SessionMetadata | None
    response: Response | None = None


@dataclass(frozen=True, slots=True)
class AfterLoginEvent:
    # The raw token is deliberately not exposed to hooks. ``session_record`` is
    # ``None`` when a ``token_issuer`` or the web framework created it.
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

    ``email`` is already canonicalized by ``normalize_email``. ``email``,
    ``email_verified`` and the ``id``, ``email`` and ``email_verified`` keys of
    ``user_info`` are read-only; hooks may adjust ``extra_fields`` and other
    ``user_info`` profile metadata.
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
    social_account: SocialAccountSnapshot
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
    # The token sent as the session cookie or bearer credential. Return a
    # different one to revoke that session instead.
    session_token: str | None = None
    scope: LogoutScope = "current"


@dataclass(frozen=True, slots=True)
class AfterLogoutEvent:
    request: HTTPRequest
    response: Response
    session_record: SessionRecord | None
    scope: LogoutScope = "current"
    revoked_count: int = 0


@dataclass(frozen=True, slots=True)
class BeforeOAuthAuthorizeEvent:
    provider: ProviderSnapshot
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

    ``provider`` and the verified ``validated_user_info`` claims select,
    auto-link or create the account; hooks may read them but not change them.
    ``user_info`` profile metadata may be adjusted, except its ``id``, ``email``
    and ``email_verified`` keys.
    """

    provider: ProviderSnapshot
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
    provider: ProviderSnapshot
    request: HTTPRequest
    user: UserSnapshot


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

    ``provider``, ``user`` and the verified ``validated_user_info`` claims are
    read-only; ``allow_login`` and the ``user_info`` profile metadata may be
    adjusted, except its ``id``, ``email`` and ``email_verified`` keys.
    """

    provider: ProviderSnapshot
    request: HTTPRequest
    user: UserSnapshot
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
    provider: ProviderSnapshot
    request: HTTPRequest
    user: UserSnapshot
    social_account: SocialAccountSnapshot


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
    user: UserSnapshot | None
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
    "LogoutScope",
    "ProviderSnapshot",
    "SocialAccountSnapshot",
    "UserSnapshot",
]
