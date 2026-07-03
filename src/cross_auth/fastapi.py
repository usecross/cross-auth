from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any, Literal, overload

from cross_web import AsyncHTTPRequest, Cookie, HTTPRequest
from cross_web import Response as CrossWebResponse
from fastapi import HTTPException
from fastapi import Request as FastAPIRequest
from fastapi import Response as FastAPIResponse

from ._config import Config
from ._context import AccountsStorage, SecondaryStorage, User
from ._email import normalize_email as _normalize_email
from ._password import authenticate
from ._request import make_http_request
from ._session import (
    ResolvedSession,
    SessionConfig,
    SessionMetadata,
    create_session,
    get_current_user,
    make_clear_cookie,
    make_session_cookie,
    resolve_config,
    resolve_current_session,
)
from ._session import (
    get_session as get_session_by_token,
)
from ._storage import (
    SessionListOrder,
    SessionListResult,
    SessionRecord,
    SessionStatus,
    SessionStorage,
)
from ._tokens import TokenIssuer
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
        trusted_origins: list[str],
        session_storage: SessionStorage | None = None,
        token_issuer: TokenIssuer | None = None,
        get_user_from_request: Callable[[HTTPRequest], User | None] | None = None,
        base_url: str | None = None,
        config: Config | None = None,
        default_next_url: str = "/",
        normalize_email: Callable[[str], str] | None = None,
    ):
        self._storage = storage
        self._accounts_storage = accounts_storage
        self._session_storage = session_storage
        self._session_config: SessionConfig | None = (config or {}).get("session")
        self._hooks = HookRegistry()
        self._normalize_email = (
            normalize_email if normalize_email is not None else _normalize_email
        )

        self._get_user_from_request = (
            get_user_from_request or self._default_get_user_from_request
        )

        self._router = AuthRouter(
            providers=providers,
            secondary_storage=storage,
            accounts_storage=accounts_storage,
            session_storage=session_storage,
            token_issuer=token_issuer,
            get_user_from_request=self._get_user_from_request,
            trusted_origins=trusted_origins,
            base_url=base_url,
            config=config,
            default_next_url=default_next_url,
            hooks=self._hooks,
            normalize_email=normalize_email,
        )

    @property
    def router(self) -> AuthRouter:
        return self._router

    def _require_session_storage(self) -> SessionStorage:
        if self._session_storage is None:
            raise RuntimeError("session_storage is required for session operations")
        return self._session_storage

    def _default_get_user_from_request(self, request: HTTPRequest) -> User | None:
        if self._session_storage is None:
            return None
        return get_current_user(
            request,
            self._session_storage,
            self._accounts_storage,
            self._session_config,
        )

    def _resolve_user(self, request: FastAPIRequest) -> User | None:
        async_request = AsyncHTTPRequest.from_fastapi(request)
        return self._get_user_from_request(make_http_request(async_request))

    def get_current_user(
        self, request: FastAPIRequest, response: FastAPIResponse
    ) -> User | None:
        # Roll the cookie before resolving the user so the refresh is captured
        # here; the resolver then re-reads the (already refreshed) record.
        self._roll_session_cookie(request, response)
        return self._resolve_user(request)

    def get_current_session(
        self, request: FastAPIRequest, response: FastAPIResponse
    ) -> SessionRecord | None:
        session_storage = self._require_session_storage()
        async_request = AsyncHTTPRequest.from_fastapi(request)
        resolution = resolve_current_session(
            make_http_request(async_request),
            session_storage,
            self._session_config,
        )
        if resolution is None:
            return None
        self._roll_cookie_for(resolution, response)
        return resolution.record

    def require_current_user(
        self, request: FastAPIRequest, response: FastAPIResponse
    ) -> User:
        self._roll_session_cookie(request, response)
        user = self._resolve_user(request)
        if user is None:
            raise HTTPException(status_code=401)
        return user

    def _roll_cookie_for(
        self, resolution: ResolvedSession, response: FastAPIResponse
    ) -> None:
        """Reissue Set-Cookie when a cookie-backed session was just refreshed.

        Sliding sessions (``update_age``) extend the stored ``expires_at`` on
        read; without re-sending the cookie the browser would still drop it at
        the original Max-Age. Bearer tokens have no cookie to roll.
        """
        if resolution.source == "cookie" and resolution.refreshed:
            cookie = make_session_cookie(resolution.token, self._session_config)
            self._set_cookie_on_response(response, cookie)

    def _roll_session_cookie(
        self, request: FastAPIRequest, response: FastAPIResponse | None
    ) -> None:
        # No response to write to, no store, or no sliding window -> nothing to do.
        if response is None or self._session_storage is None:
            return
        if resolve_config(self._session_config).get("update_age") is None:
            return
        async_request = AsyncHTTPRequest.from_fastapi(request)
        resolution = resolve_current_session(
            make_http_request(async_request),
            self._session_storage,
            self._session_config,
        )
        if resolution is not None:
            self._roll_cookie_for(resolution, response)

    def list_sessions(
        self,
        user_id: Any,
        *,
        status: SessionStatus | None = None,
        order_by: SessionListOrder = "updated_at_desc",
        limit: int = 50,
        cursor: str | None = None,
    ) -> SessionListResult:
        return self._require_session_storage().list_for_user(
            user_id,
            now=datetime.now(tz=timezone.utc),
            status=status,
            order_by=order_by,
            limit=limit,
            cursor=cursor,
        )

    def get_session(self, session_id: Any, *, user_id: Any) -> SessionRecord | None:
        session = self._require_session_storage().get_any(session_id)
        if session is None or str(session.user_id) != str(user_id):
            return None
        return session

    def revoke_session(self, session_id: Any, *, user_id: Any) -> None:
        session = self.get_session(session_id, user_id=user_id)
        if session is None:
            return
        self._require_session_storage().revoke(
            session.id,
            revoked_at=datetime.now(tz=timezone.utc),
        )

    def revoke_other_sessions(self, *, user_id: Any, keep_session_id: Any) -> int:
        return self._require_session_storage().revoke_all_for_user(
            user_id,
            revoked_at=datetime.now(tz=timezone.utc),
            except_session_id=keep_session_id,
        )

    def revoke_all_sessions(self, *, user_id: Any) -> int:
        return self._require_session_storage().revoke_all_for_user(
            user_id,
            revoked_at=datetime.now(tz=timezone.utc),
        )

    def authenticate(self, email: str, password: str) -> User | None:
        event = self._hooks.run_before(
            "authenticate",
            BeforeAuthenticateEvent(email=email, password=password),
        )

        # Normalize at the lookup only: the hook events keep the email exactly
        # as the client submitted it.
        user = authenticate(
            self._normalize_email(event.email), event.password, self._accounts_storage
        )

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
        def decorator(handler: Callable[..., object]) -> Callable[..., object]:
            self._hooks.register_before(event, handler)
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
        def decorator(handler: Callable[..., object]) -> Callable[..., object]:
            self._hooks.register_after(event, handler)
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

    def login(
        self,
        user_id: str,
        *,
        response: FastAPIResponse,
        metadata: SessionMetadata | None = None,
    ) -> None:
        session_storage = self._require_session_storage()
        hook_response = self._make_hook_response(response)
        event = self._hooks.run_before(
            "login",
            BeforeLoginEvent(user_id=user_id, response=hook_response),
        )
        resolved = resolve_config(self._session_config)
        max_age = resolved["max_age"]
        session_token, session_record = create_session(
            event.user_id,
            session_storage,
            max_age=max_age,
            metadata=metadata,
            token_hasher=resolved["token_hasher"],
        )
        cookie = make_session_cookie(session_token, self._session_config)
        self._add_cookie_to_hook_response(event.response, cookie)
        self._hooks.run_after(
            "login",
            AfterLoginEvent(
                user_id=event.user_id,
                response=event.response,
                session_record=session_record,
                cookie=cookie,
            ),
        )
        self._apply_hook_response(event.response, response)

    def logout(self, request: FastAPIRequest, *, response: FastAPIResponse) -> None:
        session_storage = self._require_session_storage()
        resolved = resolve_config(self._session_config)
        cookie_name = resolved["cookies"]["name"]
        hook_request = make_http_request(AsyncHTTPRequest.from_fastapi(request))
        hook_response = self._make_hook_response(response)
        session_token = hook_request.cookies.get(cookie_name)
        session_record = (
            get_session_by_token(
                session_token,
                session_storage,
                self._session_config,
            )
            if session_token is not None
            else None
        )
        event = self._hooks.run_before(
            "logout",
            BeforeLogoutEvent(
                request=hook_request,
                response=hook_response,
                session_record=session_record,
            ),
        )

        if event.session_record is not None:
            session_storage.revoke(
                event.session_record.id,
                revoked_at=datetime.now(tz=timezone.utc),
            )

        cookie = make_clear_cookie(self._session_config)
        self._add_cookie_to_hook_response(event.response, cookie)
        self._hooks.run_after(
            "logout",
            AfterLogoutEvent(
                request=event.request,
                response=event.response,
                session_record=event.session_record,
            ),
        )
        self._apply_hook_response(event.response, response)
