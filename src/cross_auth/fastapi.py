from __future__ import annotations

from collections.abc import Callable
from typing import Literal, overload

from cross_web import AsyncHTTPRequest, Cookie
from cross_web import Response as CrossWebResponse
from fastapi import HTTPException
from fastapi import Request as FastAPIRequest
from fastapi import Response as FastAPIResponse

from ._config import Config
from ._context import AccountsStorage, SecondaryStorage, User
from ._password import authenticate
from ._session import (
    SessionConfig,
    create_session,
    delete_session,
    get_current_user,
    make_clear_cookie,
    make_session_cookie,
    resolve_config,
)
from .hooks import (
    AfterAuthenticateEvent,
    AfterLoginEvent,
    AfterLogoutEvent,
    BeforeAuthenticateEvent,
    BeforeLoginEvent,
    BeforeLogoutEvent,
    HookRegistry,
)
from .hooks._types import (
    AfterAuthenticateHandler,
    AfterLoginHandler,
    AfterLogoutHandler,
    AfterOAuthAuthorizeHandler,
    AfterOAuthCallbackHandler,
    AfterOAuthDisconnectHandler,
    AfterOAuthFinalizeLinkHandler,
    AfterOAuthLinkHandler,
    AfterTokenAuthorizationCodeHandler,
    AfterTokenPasswordHandler,
    BeforeAuthenticateHandler,
    BeforeLoginHandler,
    BeforeLogoutHandler,
    BeforeOAuthAuthorizeHandler,
    BeforeOAuthCallbackHandler,
    BeforeOAuthDisconnectHandler,
    BeforeOAuthFinalizeLinkHandler,
    BeforeOAuthLinkHandler,
    BeforeTokenAuthorizationCodeHandler,
    BeforeTokenPasswordHandler,
    HookEventName,
)
from .hooks.registry import _event_allows_async
from .router import AuthRouter
from .social_providers.oauth import OAuth2Provider

# TODO: if we add more framework integrations, extract shared storage/session
# logic into a private _BaseCrossAuth class that framework classes inherit from.


class CrossAuth:
    def __init__(
        self,
        *,
        providers: list[OAuth2Provider],
        storage: SecondaryStorage,
        accounts_storage: AccountsStorage,
        create_token: Callable[[str], tuple[str, int]],
        trusted_origins: list[str],
        session_config: SessionConfig | None = None,
        get_user_from_request: Callable[[AsyncHTTPRequest], User | None] | None = None,
        base_url: str | None = None,
        config: Config | None = None,
        default_next_url: str = "/",
    ):
        self._storage = storage
        self._accounts_storage = accounts_storage
        self._session_config = session_config
        self._hooks = HookRegistry()

        self._get_user_from_request = (
            get_user_from_request or self._default_get_user_from_request
        )

        self._router = AuthRouter(
            providers=providers,
            secondary_storage=storage,
            accounts_storage=accounts_storage,
            get_user_from_request=self._get_user_from_request,
            create_token=create_token,
            trusted_origins=trusted_origins,
            base_url=base_url,
            config=config,
            session_enabled=True,
            session_config=self._session_config,
            default_next_url=default_next_url,
            hooks=self._hooks,
        )

    @property
    def router(self) -> AuthRouter:
        return self._router

    def _default_get_user_from_request(self, request: AsyncHTTPRequest) -> User | None:
        return get_current_user(
            request,
            self._storage,
            self._accounts_storage,
            self._session_config,
        )

    def _resolve_user(self, request: FastAPIRequest) -> User | None:
        async_request = AsyncHTTPRequest.from_fastapi(request)
        return self._get_user_from_request(async_request)

    def get_current_user(self, request: FastAPIRequest) -> User | None:
        return self._resolve_user(request)

    def require_current_user(self, request: FastAPIRequest) -> User:
        user = self._resolve_user(request)
        if user is None:
            raise HTTPException(status_code=401)
        return user

    def authenticate(self, email: str, password: str) -> User | None:
        event = self._hooks.run_before(
            "authenticate",
            BeforeAuthenticateEvent(email=email, password=password),
        )

        user = authenticate(event.email, event.password, self._accounts_storage)

        self._hooks.run_after(
            "authenticate",
            AfterAuthenticateEvent(email=event.email, user=user),
        )

        return user

    @overload
    def before(
        self, event: Literal["authenticate"]
    ) -> Callable[[BeforeAuthenticateHandler], BeforeAuthenticateHandler]: ...

    @overload
    def before(
        self, event: Literal["login"]
    ) -> Callable[[BeforeLoginHandler], BeforeLoginHandler]: ...

    @overload
    def before(
        self, event: Literal["logout"]
    ) -> Callable[[BeforeLogoutHandler], BeforeLogoutHandler]: ...

    @overload
    def before(
        self, event: Literal["oauth.authorize"]
    ) -> Callable[[BeforeOAuthAuthorizeHandler], BeforeOAuthAuthorizeHandler]: ...

    @overload
    def before(
        self, event: Literal["oauth.callback"]
    ) -> Callable[[BeforeOAuthCallbackHandler], BeforeOAuthCallbackHandler]: ...

    @overload
    def before(
        self, event: Literal["oauth.link"]
    ) -> Callable[[BeforeOAuthLinkHandler], BeforeOAuthLinkHandler]: ...

    @overload
    def before(
        self, event: Literal["oauth.finalize_link"]
    ) -> Callable[[BeforeOAuthFinalizeLinkHandler], BeforeOAuthFinalizeLinkHandler]: ...

    @overload
    def before(
        self, event: Literal["oauth.disconnect"]
    ) -> Callable[[BeforeOAuthDisconnectHandler], BeforeOAuthDisconnectHandler]: ...

    @overload
    def before(
        self, event: Literal["token.password"]
    ) -> Callable[[BeforeTokenPasswordHandler], BeforeTokenPasswordHandler]: ...

    @overload
    def before(
        self, event: Literal["token.authorization_code"]
    ) -> Callable[
        [BeforeTokenAuthorizationCodeHandler], BeforeTokenAuthorizationCodeHandler
    ]: ...

    def before(
        self, event: HookEventName
    ) -> Callable[[Callable[..., object]], Callable[..., object]]:
        allow_async = _event_allows_async(event)

        def decorator(handler: Callable[..., object]) -> Callable[..., object]:
            self._hooks.register_before(event, handler, allow_async=allow_async)
            return handler

        return decorator

    @overload
    def after(
        self, event: Literal["authenticate"]
    ) -> Callable[[AfterAuthenticateHandler], AfterAuthenticateHandler]: ...

    @overload
    def after(
        self, event: Literal["login"]
    ) -> Callable[[AfterLoginHandler], AfterLoginHandler]: ...

    @overload
    def after(
        self, event: Literal["logout"]
    ) -> Callable[[AfterLogoutHandler], AfterLogoutHandler]: ...

    @overload
    def after(
        self, event: Literal["oauth.authorize"]
    ) -> Callable[[AfterOAuthAuthorizeHandler], AfterOAuthAuthorizeHandler]: ...

    @overload
    def after(
        self, event: Literal["oauth.callback"]
    ) -> Callable[[AfterOAuthCallbackHandler], AfterOAuthCallbackHandler]: ...

    @overload
    def after(
        self, event: Literal["oauth.link"]
    ) -> Callable[[AfterOAuthLinkHandler], AfterOAuthLinkHandler]: ...

    @overload
    def after(
        self, event: Literal["oauth.finalize_link"]
    ) -> Callable[[AfterOAuthFinalizeLinkHandler], AfterOAuthFinalizeLinkHandler]: ...

    @overload
    def after(
        self, event: Literal["oauth.disconnect"]
    ) -> Callable[[AfterOAuthDisconnectHandler], AfterOAuthDisconnectHandler]: ...

    @overload
    def after(
        self, event: Literal["token.password"]
    ) -> Callable[[AfterTokenPasswordHandler], AfterTokenPasswordHandler]: ...

    @overload
    def after(
        self, event: Literal["token.authorization_code"]
    ) -> Callable[
        [AfterTokenAuthorizationCodeHandler], AfterTokenAuthorizationCodeHandler
    ]: ...

    def after(
        self, event: HookEventName
    ) -> Callable[[Callable[..., object]], Callable[..., object]]:
        allow_async = _event_allows_async(event)

        def decorator(handler: Callable[..., object]) -> Callable[..., object]:
            self._hooks.register_after(event, handler, allow_async=allow_async)
            return handler

        return decorator

    def _set_cookie_on_response(
        self, response: FastAPIResponse, cookie: Cookie
    ) -> None:
        response.set_cookie(
            key=cookie.name,
            value=cookie.value,
            max_age=cookie.max_age,
            path=cookie.path or "/",
            domain=cookie.domain,
            secure=cookie.secure,
            httponly=cookie.httponly,
            samesite=cookie.samesite,
        )

    def _make_hook_response(self, response: FastAPIResponse) -> CrossWebResponse:
        return CrossWebResponse(
            status_code=response.status_code,
            headers={
                name: value
                for name, value in response.headers.items()
                if name.lower() != "set-cookie"
            },
            cookies=[],
        )

    # TODO: refactor this when we improve cross-web
    def _add_cookie_to_hook_response(
        self, response: CrossWebResponse, cookie: Cookie
    ) -> None:
        if response.cookies is None:
            response.cookies = []
        response.cookies.append(cookie)

    def _apply_hook_response(
        self, source: CrossWebResponse, target: FastAPIResponse
    ) -> None:
        target.status_code = source.status_code

        for name, value in (source.headers or {}).items():
            if name.lower() == "set-cookie":
                continue
            target.headers[name] = value

        for cookie in source.cookies or []:
            self._set_cookie_on_response(target, cookie)

    def login(self, user_id: str, *, response: FastAPIResponse) -> None:
        hook_response = self._make_hook_response(response)
        event = self._hooks.run_before(
            "login",
            BeforeLoginEvent(user_id=user_id, response=hook_response),
        )
        resolved = resolve_config(self._session_config)
        max_age = resolved["max_age"]
        session_id, session_data = create_session(
            event.user_id, self._storage, max_age=max_age
        )
        cookie = make_session_cookie(session_id, self._session_config)
        self._add_cookie_to_hook_response(event.response, cookie)
        self._hooks.run_after(
            "login",
            AfterLoginEvent(
                user_id=event.user_id,
                response=event.response,
                session_id=session_id,
                session_data=session_data,
                cookie=cookie,
            ),
        )
        self._apply_hook_response(event.response, response)

    def logout(self, request: FastAPIRequest, *, response: FastAPIResponse) -> None:
        resolved = resolve_config(self._session_config)
        cookie_name = resolved["cookie_name"]
        hook_request = AsyncHTTPRequest.from_fastapi(request)
        hook_response = self._make_hook_response(response)
        event = self._hooks.run_before(
            "logout",
            BeforeLogoutEvent(
                request=hook_request,
                response=hook_response,
                session_id=hook_request.cookies.get(cookie_name),
            ),
        )

        if event.session_id is not None:
            delete_session(event.session_id, self._storage)

        cookie = make_clear_cookie(self._session_config)
        self._add_cookie_to_hook_response(event.response, cookie)
        self._hooks.run_after(
            "logout",
            AfterLogoutEvent(
                request=event.request,
                response=event.response,
                session_id=event.session_id,
            ),
        )
        self._apply_hook_response(event.response, response)
