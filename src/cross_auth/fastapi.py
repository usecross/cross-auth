from __future__ import annotations

import hashlib
import secrets
import warnings
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any, Literal, cast, overload

from cross_web import AsyncHTTPRequest, Cookie, HTTPRequest
from cross_web import Response as CrossWebResponse
from fastapi import HTTPException
from fastapi import Request as FastAPIRequest
from fastapi import Response as FastAPIResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from ._auth_flow import resolve_or_create_user
from ._config import Config
from ._context import AccountsStorage, SecondaryStorage, User
from ._email import normalize_email as _normalize_email
from ._password import authenticate
from ._request import make_http_request
from ._session import (
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
    AfterOAuthIdTokenEvent,
    AfterSessionIssueEvent,
    BeforeAuthenticateEvent,
    BeforeLoginEvent,
    BeforeLogoutEvent,
    BeforeOAuthIdTokenEvent,
    BeforeSessionIssueEvent,
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
    AfterOAuthIdTokenHandler,
    AfterOAuthLinkHandler,
    AfterSessionIssueHandler,
    AfterTokenAuthorizationCodeHandler,
    AfterTokenPasswordHandler,
    BeforeAuthenticateHandler,
    BeforeLoginHandler,
    BeforeLogoutHandler,
    BeforeOAuthAuthorizeHandler,
    BeforeOAuthCallbackHandler,
    BeforeOAuthDisconnectHandler,
    BeforeOAuthFinalizeLinkHandler,
    BeforeOAuthIdTokenHandler,
    BeforeOAuthLinkHandler,
    BeforeSessionIssueHandler,
    BeforeTokenAuthorizationCodeHandler,
    BeforeTokenPasswordHandler,
    HookEventName,
)
from .exceptions import CrossAuthException
from .router import AuthRouter
from .social_providers.oauth import OAuth2Exception, OAuth2Provider, UserInfo
from .social_providers.oidc import OIDCProvider

# TODO: if we add more framework integrations, extract shared storage/session
# logic into a private _BaseCrossAuth class that framework classes inherit from.


class _NoTokenResponse:
    """Native id_token sign-ins have no OAuth token exchange: there is no
    access or refresh token to store on the social account."""

    access_token = None
    refresh_token = None
    access_token_expires_at = None
    refresh_token_expires_at = None
    scope = None


_NO_TOKEN_RESPONSE = _NoTokenResponse()


def _verify_nonce(claims: dict[str, Any], nonce: str) -> None:
    # The app sends the raw nonce; the token carries either the raw value
    # (Google) or its SHA-256 hex digest (Apple hashes what the app sent).
    claim = claims.get("nonce")
    if not isinstance(claim, str):
        raise OAuth2Exception(
            error="invalid_token",
            error_description="id_token has no nonce claim to verify",
        )
    hashed = hashlib.sha256(nonce.encode("utf-8")).hexdigest()
    if not (
        secrets.compare_digest(claim, nonce) or secrets.compare_digest(claim, hashed)
    ):
        raise OAuth2Exception(
            error="invalid_token",
            error_description="id_token nonce mismatch",
        )


# request.state slots shared between CrossAuth and SessionCookieMiddleware. The
# middleware marks the sink on the way in; session reads queue rolled cookies
# as they resolve; the middleware serializes them onto the outgoing response.
_COOKIE_SINK_STATE_KEY = "cross_auth_cookie_sink"
_ROLLED_COOKIES_STATE_KEY = "cross_auth_rolled_cookies"


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
        self._providers: dict[str, OAuth2Provider] = {
            provider.id: provider for provider in providers
        }

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

    def get_current_user(self, request: FastAPIRequest) -> User | None:
        """Resolve the current user from the request's session.

        Works both as a FastAPI dependency and called directly (shared-context
        builders, GraphQL resolvers, template helpers). With sliding sessions
        (``update_age``) the stored record refreshes on read; install
        ``SessionCookieMiddleware`` so the rolled cookie also reaches the
        browser.
        """
        # Refresh (and queue the rolled cookie) before resolving the user so
        # the resolver re-reads the already-refreshed record.
        self._queue_session_refresh(request)
        return self._resolve_user(request)

    def get_current_session(self, request: FastAPIRequest) -> SessionRecord | None:
        session_storage = self._require_session_storage()
        async_request = AsyncHTTPRequest.from_fastapi(request)
        resolution = resolve_current_session(
            make_http_request(async_request),
            session_storage,
            self._session_config,
        )
        if resolution is None:
            return None
        # Sliding sessions extend the stored expires_at on read; without
        # re-sending the cookie the browser would still drop it at the
        # original Max-Age. Bearer tokens have no cookie to roll.
        if resolution.source == "cookie" and resolution.refreshed:
            self._queue_rolled_cookie(
                request, make_session_cookie(resolution.token, self._session_config)
            )
        return resolution.record

    def require_current_user(self, request: FastAPIRequest) -> User:
        user = self.get_current_user(request)
        if user is None:
            raise HTTPException(status_code=401)
        return user

    def _queue_session_refresh(self, request: FastAPIRequest) -> None:
        # No store or no sliding window -> reads never refresh anything.
        if self._session_storage is None:
            return
        if resolve_config(self._session_config).get("update_age") is None:
            return
        async_request = AsyncHTTPRequest.from_fastapi(request)
        resolution = resolve_current_session(
            make_http_request(async_request),
            self._session_storage,
            self._session_config,
        )
        if (
            resolution is not None
            and resolution.source == "cookie"
            and resolution.refreshed
        ):
            self._queue_rolled_cookie(
                request, make_session_cookie(resolution.token, self._session_config)
            )

    def _queue_rolled_cookie(self, request: FastAPIRequest, cookie: Cookie) -> None:
        state = request.scope.setdefault("state", {})
        if _COOKIE_SINK_STATE_KEY not in state:
            warnings.warn(
                "A sliding session refreshed but SessionCookieMiddleware is "
                "not installed, so the rolled session cookie cannot reach the "
                "browser and the user will be logged out at the cookie's "
                "original Max-Age. Add "
                "`app.add_middleware(SessionCookieMiddleware)`.",
                stacklevel=2,
            )
            return
        state.setdefault(_ROLLED_COOKIES_STATE_KEY, []).append(cookie)

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

    def sign_in_with_id_token(
        self,
        provider: str,
        id_token: str,
        *,
        user_info: dict[str, Any] | None = None,
        nonce: str | None = None,
    ) -> tuple[User, bool]:
        """Sign in a native/SDK login by validating a provider ``id_token``.

        The headless sibling of the OAuth callback: Apple's ASAuthorization or
        Google's Credential Manager hand the app a signed id_token, and the
        app posts it to your API (e.g. a GraphQL sign-in mutation). The token
        is validated against the provider's JWKS, then the user is found or
        created by the same core the web callback uses — normalized email
        lookup, the auto-link policy gate, and the accounts-storage signup
        hooks. Returns ``(user, created)``; pair it with
        ``issue_session_token`` to hand the client a bearer token.

        ``user_info`` overlays the token claims for data the provider delivers
        outside the token — Apple sends the user's name only on the first
        authorization, and only to the app. ``nonce`` is the raw value the app
        generated for the provider request; when given, it must match the
        token's nonce claim (raw or SHA-256, Apple hashes it). Runs the
        ``oauth.id_token`` hooks.
        """
        registered = self._providers.get(provider)
        if registered is None:
            raise CrossAuthException(
                "invalid_request",
                error_description=f"Unknown provider: {provider!r}",
            )
        if not isinstance(registered, OIDCProvider):
            raise CrossAuthException(
                "invalid_request",
                error_description=(
                    f"Provider {provider!r} does not issue id_tokens; only "
                    "OIDC providers support id_token sign-in"
                ),
            )

        event = self._hooks.run_before(
            "oauth.id_token",
            BeforeOAuthIdTokenEvent(
                provider=provider, id_token=id_token, user_info=user_info
            ),
        )

        claims = registered.validate_id_token(event.id_token, self._storage)
        if nonce is not None:
            _verify_nonce(claims, nonce)

        merged: dict[str, Any] = {
            **registered.extract_user_info_from_claims(claims),
            **(event.user_info or {}),
        }
        validated = registered.validate_user_info(cast("UserInfo", merged))

        resolved_user, resolved_account = resolve_or_create_user(
            provider=registered,
            context=self._router.context,
            validated=validated,
            user_info=merged,
            token_response=_NO_TOKEN_RESPONSE,
        )

        self._hooks.run_after(
            "oauth.id_token",
            AfterOAuthIdTokenEvent(
                provider=provider,
                user=resolved_user.user,
                created=resolved_user.created,
                social_account=resolved_account.account,
            ),
        )
        return resolved_user.user, resolved_user.created

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
        self, event: Literal["session.issue"]
    ) -> Callable[[BeforeSessionIssueHandler], BeforeSessionIssueHandler]: ...

    @overload
    def before(
        self, event: Literal["oauth.id_token"]
    ) -> Callable[[BeforeOAuthIdTokenHandler], BeforeOAuthIdTokenHandler]: ...

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
        self, event: Literal["session.issue"]
    ) -> Callable[[AfterSessionIssueHandler], AfterSessionIssueHandler]: ...

    @overload
    def after(
        self, event: Literal["oauth.id_token"]
    ) -> Callable[[AfterOAuthIdTokenHandler], AfterOAuthIdTokenHandler]: ...

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

    def issue_session_token(
        self,
        user_id: str,
        *,
        max_age: int | None = None,
        metadata: SessionMetadata | None = None,
    ) -> tuple[str, SessionRecord]:
        """Create a session and return its bearer token with the record.

        For clients that authenticate outside the built-in ``/token`` endpoint
        and outside a browser — a GraphQL sign-in mutation for a native app, a
        CLI. The returned token is the same revocable opaque token ``/token``
        issues: clients send it as ``Authorization: Bearer ...`` and
        ``get_current_user`` resolves it. ``max_age`` overrides the configured
        session lifetime (e.g. longer-lived mobile sessions than browser
        cookies). No cookie is set; the ``session.issue`` hooks run around the
        creation, and the raw token is never exposed to them.
        """
        session_storage = self._require_session_storage()
        event = self._hooks.run_before(
            "session.issue",
            BeforeSessionIssueEvent(
                user_id=user_id, max_age=max_age, metadata=metadata
            ),
        )
        resolved = resolve_config(self._session_config)
        session_token, record = create_session(
            event.user_id,
            session_storage,
            max_age=event.max_age if event.max_age is not None else resolved["max_age"],
            metadata=event.metadata,
            token_hasher=resolved["token_hasher"],
        )
        self._hooks.run_after(
            "session.issue",
            AfterSessionIssueEvent(user_id=event.user_id, session_record=record),
        )
        return session_token, record

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


def _serialize_cookie(cookie: Cookie) -> bytes:
    # Reuse starlette's Set-Cookie serialization instead of hand-rolling it.
    scratch = FastAPIResponse()
    scratch.set_cookie(
        key=cookie.name,
        value=cookie.value,
        max_age=cookie.max_age,
        path=cookie.path or "/",
        domain=cookie.domain,
        secure=cookie.secure,
        httponly=cookie.httponly,
        samesite=cookie.samesite,
    )
    return scratch.headers["set-cookie"].encode("latin-1")


class SessionCookieMiddleware:
    """Delivers rolled sliding-session cookies on the outgoing response.

    Install once when sessions are configured with ``update_age``::

        app.add_middleware(SessionCookieMiddleware)

    Session reads that refresh a cookie-backed session queue the rolled cookie
    on the request state; this middleware serializes it onto whatever response
    the handler produces — including responses returned directly (redirects,
    streaming, server-rendered pages), which a dependency-injected ``Response``
    can never reach. A cookie the handler already set itself (``logout``
    clearing it, ``login`` replacing it) wins: the rolled copy is dropped
    instead of fighting it. Without ``update_age`` reads never roll a cookie
    and the middleware is inert.
    """

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        state = scope.setdefault("state", {})
        state[_COOKIE_SINK_STATE_KEY] = True

        async def send_with_rolled_cookies(message: Message) -> None:
            if message["type"] == "http.response.start":
                for cookie in state.get(_ROLLED_COOKIES_STATE_KEY, []):
                    _append_unless_cookie_set(message, cookie)
            await send(message)

        await self.app(scope, receive, send_with_rolled_cookies)


def _append_unless_cookie_set(message: Message, cookie: Cookie) -> None:
    headers: list[tuple[bytes, bytes]] = message.setdefault("headers", [])
    prefix = f"{cookie.name}=".encode("latin-1")
    for name, value in headers:
        if name.lower() == b"set-cookie" and value.startswith(prefix):
            return
    headers.append((b"set-cookie", _serialize_cookie(cookie)))
