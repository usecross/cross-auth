from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Literal, TypeAlias

from .events import (
    AfterAuthenticateEvent,
    AfterLoginEvent,
    AfterLogoutEvent,
    AfterOAuthAuthorizeEvent,
    AfterOAuthCallbackEvent,
    AfterOAuthFinalizeLinkEvent,
    AfterOAuthLinkEvent,
    AfterTokenAuthorizationCodeEvent,
    AfterTokenPasswordEvent,
    BeforeAuthenticateEvent,
    BeforeLoginEvent,
    BeforeLogoutEvent,
    BeforeOAuthAuthorizeEvent,
    BeforeOAuthCallbackEvent,
    BeforeOAuthFinalizeLinkEvent,
    BeforeOAuthLinkEvent,
    BeforeTokenAuthorizationCodeEvent,
    BeforeTokenPasswordEvent,
)

HookEventName: TypeAlias = Literal[
    "authenticate",
    "login",
    "logout",
    "oauth.authorize",
    "oauth.callback",
    "oauth.link",
    "oauth.finalize_link",
    "token.password",
    "token.authorization_code",
]

_SYNC_EVENT_NAMES: frozenset[str] = frozenset({"authenticate", "login", "logout"})
_ALL_EVENT_NAMES: frozenset[str] = frozenset(
    {
        "authenticate",
        "login",
        "logout",
        "oauth.authorize",
        "oauth.callback",
        "oauth.link",
        "oauth.finalize_link",
        "token.password",
        "token.authorization_code",
    }
)
_RETURNABLE_BEFORE_EVENT_NAMES: frozenset[str] = frozenset(
    {
        "authenticate",
        "login",
        "logout",
        "oauth.authorize",
        "oauth.callback",
        "oauth.finalize_link",
    }
)

BeforeAuthenticateHandler: TypeAlias = Callable[
    [BeforeAuthenticateEvent], BeforeAuthenticateEvent | None
]
AfterAuthenticateHandler: TypeAlias = Callable[[AfterAuthenticateEvent], None]

BeforeLoginHandler: TypeAlias = Callable[[BeforeLoginEvent], BeforeLoginEvent | None]
AfterLoginHandler: TypeAlias = Callable[[AfterLoginEvent], None]

BeforeLogoutHandler: TypeAlias = Callable[[BeforeLogoutEvent], BeforeLogoutEvent | None]
AfterLogoutHandler: TypeAlias = Callable[[AfterLogoutEvent], None]

BeforeOAuthAuthorizeHandler: TypeAlias = Callable[
    [BeforeOAuthAuthorizeEvent],
    BeforeOAuthAuthorizeEvent | Awaitable[BeforeOAuthAuthorizeEvent | None] | None,
]
AfterOAuthAuthorizeHandler: TypeAlias = Callable[
    [AfterOAuthAuthorizeEvent], Awaitable[None] | None
]

BeforeOAuthCallbackHandler: TypeAlias = Callable[
    [BeforeOAuthCallbackEvent],
    BeforeOAuthCallbackEvent | Awaitable[BeforeOAuthCallbackEvent | None] | None,
]
AfterOAuthCallbackHandler: TypeAlias = Callable[
    [AfterOAuthCallbackEvent], Awaitable[None] | None
]

BeforeOAuthLinkHandler: TypeAlias = Callable[
    [BeforeOAuthLinkEvent], Awaitable[None] | None
]
AfterOAuthLinkHandler: TypeAlias = Callable[
    [AfterOAuthLinkEvent], Awaitable[None] | None
]

BeforeOAuthFinalizeLinkHandler: TypeAlias = Callable[
    [BeforeOAuthFinalizeLinkEvent],
    BeforeOAuthFinalizeLinkEvent
    | Awaitable[BeforeOAuthFinalizeLinkEvent | None]
    | None,
]
AfterOAuthFinalizeLinkHandler: TypeAlias = Callable[
    [AfterOAuthFinalizeLinkEvent], Awaitable[None] | None
]

BeforeTokenPasswordHandler: TypeAlias = Callable[
    [BeforeTokenPasswordEvent], Awaitable[None] | None
]
AfterTokenPasswordHandler: TypeAlias = Callable[
    [AfterTokenPasswordEvent], Awaitable[None] | None
]

BeforeTokenAuthorizationCodeHandler: TypeAlias = Callable[
    [BeforeTokenAuthorizationCodeEvent], Awaitable[None] | None
]
AfterTokenAuthorizationCodeHandler: TypeAlias = Callable[
    [AfterTokenAuthorizationCodeEvent], Awaitable[None] | None
]
