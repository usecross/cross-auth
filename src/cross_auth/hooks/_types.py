from __future__ import annotations

from collections.abc import Callable
from typing import Literal, TypeAlias

from .events import (
    AfterAuthenticateEvent,
    AfterLoginEvent,
    AfterLogoutEvent,
    AfterOAuthAuthorizeEvent,
    AfterOAuthCallbackEvent,
    AfterOAuthDisconnectEvent,
    AfterOAuthFinalizeLinkEvent,
    AfterOAuthIdTokenEvent,
    AfterOAuthLinkEvent,
    AfterSessionIssueEvent,
    AfterSocialAccountCreateEvent,
    AfterSocialAccountUpdateEvent,
    AfterTokenAuthorizationCodeEvent,
    AfterTokenPasswordEvent,
    AfterUserCreateEvent,
    BeforeAuthenticateEvent,
    BeforeLoginEvent,
    BeforeLogoutEvent,
    BeforeOAuthAuthorizeEvent,
    BeforeOAuthCallbackEvent,
    BeforeOAuthDisconnectEvent,
    BeforeOAuthFinalizeLinkEvent,
    BeforeOAuthIdTokenEvent,
    BeforeOAuthLinkEvent,
    BeforeSessionIssueEvent,
    BeforeSocialAccountCreateEvent,
    BeforeSocialAccountUpdateEvent,
    BeforeTokenAuthorizationCodeEvent,
    BeforeTokenPasswordEvent,
    BeforeUserCreateEvent,
)

HookEventName: TypeAlias = Literal[
    "authenticate",
    "login",
    "logout",
    "session.issue",
    "user.create",
    "social_account.create",
    "social_account.update",
    "oauth.authorize",
    "oauth.callback",
    "oauth.id_token",
    "oauth.link",
    "oauth.finalize_link",
    "oauth.disconnect",
    "token.password",
    "token.authorization_code",
]

_ALL_EVENT_NAMES: frozenset[str] = frozenset(
    {
        "authenticate",
        "login",
        "logout",
        "session.issue",
        "user.create",
        "social_account.create",
        "social_account.update",
        "oauth.authorize",
        "oauth.callback",
        "oauth.id_token",
        "oauth.link",
        "oauth.finalize_link",
        "oauth.disconnect",
        "token.password",
        "token.authorization_code",
    }
)
_RETURNABLE_BEFORE_EVENT_NAMES: frozenset[str] = frozenset(
    {
        "authenticate",
        "login",
        "logout",
        "session.issue",
        "user.create",
        "social_account.create",
        "social_account.update",
        "oauth.authorize",
        "oauth.callback",
        "oauth.id_token",
        "oauth.finalize_link",
    }
)

BeforeAuthenticateHandler: TypeAlias = Callable[
    [BeforeAuthenticateEvent], BeforeAuthenticateEvent | None
]
BeforeOAuthIdTokenHandler: TypeAlias = Callable[
    [BeforeOAuthIdTokenEvent], BeforeOAuthIdTokenEvent | None
]
AfterOAuthIdTokenHandler: TypeAlias = Callable[[AfterOAuthIdTokenEvent], None]
BeforeSessionIssueHandler: TypeAlias = Callable[
    [BeforeSessionIssueEvent], BeforeSessionIssueEvent | None
]
AfterSessionIssueHandler: TypeAlias = Callable[[AfterSessionIssueEvent], None]
BeforeUserCreateHandler: TypeAlias = Callable[
    [BeforeUserCreateEvent], BeforeUserCreateEvent | None
]
AfterUserCreateHandler: TypeAlias = Callable[[AfterUserCreateEvent], None]
BeforeSocialAccountCreateHandler: TypeAlias = Callable[
    [BeforeSocialAccountCreateEvent], BeforeSocialAccountCreateEvent | None
]
BeforeSocialAccountUpdateHandler: TypeAlias = Callable[
    [BeforeSocialAccountUpdateEvent], BeforeSocialAccountUpdateEvent | None
]
_BeforeSocialAccountCreateOrUpdateHandler: TypeAlias = Callable[
    [BeforeSocialAccountCreateEvent | BeforeSocialAccountUpdateEvent],
    BeforeSocialAccountCreateEvent | BeforeSocialAccountUpdateEvent | None,
]
AfterSocialAccountCreateHandler: TypeAlias = Callable[
    [AfterSocialAccountCreateEvent], None
]
AfterSocialAccountUpdateHandler: TypeAlias = Callable[
    [AfterSocialAccountUpdateEvent], None
]
_AfterSocialAccountCreateOrUpdateHandler: TypeAlias = Callable[
    [AfterSocialAccountCreateEvent | AfterSocialAccountUpdateEvent], None
]
AfterAuthenticateHandler: TypeAlias = Callable[[AfterAuthenticateEvent], None]

BeforeLoginHandler: TypeAlias = Callable[[BeforeLoginEvent], BeforeLoginEvent | None]
AfterLoginHandler: TypeAlias = Callable[[AfterLoginEvent], None]

BeforeLogoutHandler: TypeAlias = Callable[[BeforeLogoutEvent], BeforeLogoutEvent | None]
AfterLogoutHandler: TypeAlias = Callable[[AfterLogoutEvent], None]

BeforeOAuthAuthorizeHandler: TypeAlias = Callable[
    [BeforeOAuthAuthorizeEvent],
    BeforeOAuthAuthorizeEvent | None,
]
AfterOAuthAuthorizeHandler: TypeAlias = Callable[[AfterOAuthAuthorizeEvent], None]

BeforeOAuthCallbackHandler: TypeAlias = Callable[
    [BeforeOAuthCallbackEvent],
    BeforeOAuthCallbackEvent | None,
]
AfterOAuthCallbackHandler: TypeAlias = Callable[[AfterOAuthCallbackEvent], None]

BeforeOAuthLinkHandler: TypeAlias = Callable[[BeforeOAuthLinkEvent], None]
AfterOAuthLinkHandler: TypeAlias = Callable[[AfterOAuthLinkEvent], None]

BeforeOAuthFinalizeLinkHandler: TypeAlias = Callable[
    [BeforeOAuthFinalizeLinkEvent],
    BeforeOAuthFinalizeLinkEvent | None,
]
AfterOAuthFinalizeLinkHandler: TypeAlias = Callable[[AfterOAuthFinalizeLinkEvent], None]

BeforeOAuthDisconnectHandler: TypeAlias = Callable[[BeforeOAuthDisconnectEvent], None]
AfterOAuthDisconnectHandler: TypeAlias = Callable[[AfterOAuthDisconnectEvent], None]

BeforeTokenPasswordHandler: TypeAlias = Callable[[BeforeTokenPasswordEvent], None]
AfterTokenPasswordHandler: TypeAlias = Callable[[AfterTokenPasswordEvent], None]

BeforeTokenAuthorizationCodeHandler: TypeAlias = Callable[
    [BeforeTokenAuthorizationCodeEvent], None
]
AfterTokenAuthorizationCodeHandler: TypeAlias = Callable[
    [AfterTokenAuthorizationCodeEvent], None
]
