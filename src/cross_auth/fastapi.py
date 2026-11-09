from __future__ import annotations

import warnings
from collections.abc import Callable
from datetime import datetime, timezone
from typing import (
    Any,
    Concatenate,
    Literal,
    NamedTuple,
    ParamSpec,
    Protocol,
    TypeVar,
    overload,
)

from cross_web import AsyncHTTPRequest, HTTPRequest
from cross_web import Response as CrossWebResponse
from fastapi import HTTPException
from fastapi import Request as FastAPIRequest
from fastapi import Response as FastAPIResponse

from ._accounts import require_committed_accounts
from ._config import Config
from ._fastapi_session import SessionCookieMiddleware as SessionCookieMiddleware
from ._fastapi_session import queue_rolled_cookie, set_cookie
from ._login import (
    issue_bearer_session,
    login_with_session,
    logout_session,
    revoke_user_session,
    revoke_user_sessions,
)
from ._native import resolve_id_token_user as _resolve_id_token_user
from ._oauth_server import OAuthServer
from ._password import authenticate
from ._request import make_http_request
from ._session import (
    AuthenticatedSession,
    SessionMetadata,
    get_current_user,
    get_user_session,
    make_session_cookie,
    resolve_config,
    resolve_current_session,
)
from ._setup import build_auth_setup
from ._storage import (
    AccountsStorage,
    SecondaryStorage,
    SessionListOrder,
    SessionListResult,
    SessionRecord,
    SessionStatus,
    SessionStorage,
    User,
)
from ._tokens import TokenKind
from .hooks import (
    AfterAuthenticateEvent,
    AfterLoginEvent,
    AfterLogoutEvent,
    AfterOAuthAuthorizeEvent,
    AfterOAuthCallbackEvent,
    AfterOAuthDisconnectEvent,
    AfterOAuthFinalizeLinkEvent,
    AfterOAuthIdTokenEvent,
    AfterOAuthLinkEvent,
    AfterSessionRevokeEvent,
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
    BeforeSessionRevokeEvent,
    BeforeSocialAccountCreateEvent,
    BeforeSocialAccountUpdateEvent,
    BeforeTokenAuthorizationCodeEvent,
    BeforeTokenPasswordEvent,
    BeforeUserCreateEvent,
    HookRegistry,
    LogoutScope,
)
from .hooks._types import HookEventName
from .router import _TRUSTED_ORIGINS_DEPRECATION, AuthRouter
from .social_providers.oauth import OAuth2Provider

_P = ParamSpec("_P")
_EventT = TypeVar("_EventT")
_ReturnT = TypeVar("_ReturnT")


class _HookDecorator(Protocol[_EventT, _ReturnT]):
    def __call__(
        self,
        handler: Callable[Concatenate[_EventT, _P], _ReturnT],
        /,
    ) -> Callable[Concatenate[_EventT, _P], _ReturnT]: ...


_SpecificSocialAccountEventT = TypeVar("_SpecificSocialAccountEventT")
_SpecificSocialAccountReturnT = TypeVar("_SpecificSocialAccountReturnT")
_CombinedSocialAccountEventT = TypeVar("_CombinedSocialAccountEventT")
_CombinedSocialAccountReturnT = TypeVar("_CombinedSocialAccountReturnT")


class _SocialAccountDecorator(
    Protocol[
        _SpecificSocialAccountEventT,
        _SpecificSocialAccountReturnT,
        _CombinedSocialAccountEventT,
        _CombinedSocialAccountReturnT,
    ]
):
    @overload
    def __call__(
        self,
        handler: Callable[
            Concatenate[_CombinedSocialAccountEventT, _P],
            _CombinedSocialAccountReturnT,
        ],
        /,
    ) -> Callable[
        Concatenate[_CombinedSocialAccountEventT, _P],
        _CombinedSocialAccountReturnT,
    ]: ...

    @overload
    def __call__(
        self,
        handler: Callable[
            Concatenate[_SpecificSocialAccountEventT, _P],
            _SpecificSocialAccountReturnT,
        ],
        /,
    ) -> Callable[
        Concatenate[_SpecificSocialAccountEventT, _P],
        _SpecificSocialAccountReturnT,
    ]: ...


class IdTokenSignIn(NamedTuple):
    """What ``CrossAuth.sign_in_with_id_token`` returns: the bearer session it
    issued and the user it signed in."""

    token: str
    session_record: SessionRecord
    user: User
    created: bool


class CrossAuth:
    def __init__(
        self,
        *,
        providers: list[OAuth2Provider],
        storage: SecondaryStorage,
        accounts_storage: AccountsStorage,
        trusted_origins: list[str] | None = None,
        session_storage: SessionStorage | None = None,
        get_user_from_request: Callable[[HTTPRequest], User | None] | None = None,
        base_url: str | None = None,
        config: Config | None = None,
        default_next_url: str = "/",
        normalize_email: Callable[[str], str] | None = None,
        oauth_server: OAuthServer | None = None,
    ):
        if trusted_origins is not None:
            warnings.warn(
                _TRUSTED_ORIGINS_DEPRECATION, DeprecationWarning, stacklevel=2
            )
        # The default resolver is bound before the context exists; it reads the
        # context's storage/session settings only when a request arrives.
        self._setup = build_auth_setup(
            providers=providers,
            secondary_storage=storage,
            accounts_storage=accounts_storage,
            session_storage=session_storage,
            get_user_from_request=(
                self._default_get_user_from_request
                if get_user_from_request is None
                else get_user_from_request
            ),
            base_url=base_url,
            config=config,
            default_next_url=default_next_url,
            hooks=HookRegistry(),
            normalize_email=normalize_email,
            oauth_server=oauth_server,
        )
        self._context = self._setup.context
        self._router = AuthRouter._from_setup(self._setup)

    @property
    def router(self) -> AuthRouter:
        return self._router

    def _require_session_storage(self) -> SessionStorage:
        session_storage = self._context.session_storage
        if session_storage is None:
            raise RuntimeError("session_storage is required for session operations")
        return session_storage

    def _default_get_user_from_request(self, request: HTTPRequest) -> User | None:
        context = self._context
        if context.session_storage is None:
            return None
        return get_current_user(
            request,
            context.session_storage,
            context.accounts_storage,
            context.session_config,
        )

    def _resolve_user(self, request: FastAPIRequest) -> User | None:
        async_request = AsyncHTTPRequest.from_fastapi(request)
        return self._context.get_user_from_request(make_http_request(async_request))

    def get_current_user(self, request: FastAPIRequest) -> User | None:
        """Resolve the current user from the request's session.

        Works both as a FastAPI dependency and called directly (shared-context
        builders, GraphQL resolvers, template helpers). With sliding sessions
        (``update_age``) the stored record refreshes on read; install
        ``SessionCookieMiddleware`` so the rolled cookie also reaches the
        browser.
        """
        if self._context.get_user_from_request != self._default_get_user_from_request:
            # Preserve the custom-resolver contract: sliding sessions refresh
            # implicitly before the callback runs, even when the callback uses
            # another authentication mechanism.
            self._queue_session_refresh(request)
            return self._resolve_user(request)

        if self._context.session_storage is None:
            return None
        session = self.get_current_session(request)
        if session is None:
            return None
        return self._context.accounts_storage.find_user_by_id(session.user_id)

    def get_current_session(self, request: FastAPIRequest) -> SessionRecord | None:
        session_storage = self._require_session_storage()
        async_request = AsyncHTTPRequest.from_fastapi(request)
        resolution = resolve_current_session(
            make_http_request(async_request),
            session_storage,
            self._context.session_config,
        )
        if resolution is None:
            return None
        # Sliding sessions extend the stored expires_at on read; without
        # re-sending the cookie the browser would still drop it at the
        # original Max-Age. Bearer tokens have no cookie to roll.
        if resolution.source == "cookie" and resolution.refreshed:
            queue_rolled_cookie(
                request,
                make_session_cookie(resolution.token, self._context.session_config),
            )
        return resolution.record

    def identify_token(self, token: str) -> TokenKind | None:
        """Name the kind of Cross-Auth token ``token`` looks like, or ``None``.

        Returns ``"session"`` when the session ``token_prefix`` is configured
        and ``token`` has that prefix and a valid checksum. This only reads
        the token's shape and does not authenticate it: a well-formed token
        can be unknown, expired or revoked, and sessions issued before the
        prefix was set are not recognized. Use ``get_current_user`` to
        authenticate.
        """
        return self._context.identify_token(token)

    def authenticate_session_token(
        self, token: str, *, db_session: object | None = None
    ) -> AuthenticatedSession | None:
        """Return the active session ``token`` belongs to and its user.

        Returns ``None`` when the token is unknown, revoked or expired, or when
        the accounts storage does not return its user. Unlike
        ``get_current_user``, this never calls ``get_user_from_request``, so a
        custom resolver can use it for session tokens.

        Pass ``db_session`` to load the user in your own database session, so
        the returned user belongs to it: its relationships load lazily and you
        can change and commit it. The accounts storage must have a
        ``with_read_session`` method, as the SQLModel one does.
        """
        return self._context.authenticate_session_token(token, db_session=db_session)

    def require_current_user(self, request: FastAPIRequest) -> User:
        user = self.get_current_user(request)
        if user is None:
            raise HTTPException(status_code=401)
        return user

    def _queue_session_refresh(self, request: FastAPIRequest) -> None:
        session_storage = self._context.session_storage
        if session_storage is None:
            return
        if resolve_config(self._context.session_config).get("update_age") is None:
            return
        self.get_current_session(request)

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
        return get_user_session(
            session_id, self._require_session_storage(), user_id=user_id
        )

    def revoke_session(self, session_id: Any, *, user_id: Any) -> bool:
        """Revoke one of the user's sessions; another user's session is ignored.

        Runs the ``session.revoke`` hooks, with ``request`` set to ``None``.
        Returns whether an active session was revoked.
        """
        session = self.get_session(session_id, user_id=user_id)
        if session is None:
            return False
        revoked = revoke_user_session(
            session,
            hooks=self._context.hooks,
            session_storage=self._require_session_storage(),
        )
        return revoked > 0

    def revoke_other_sessions(self, *, user_id: Any, keep_session_id: Any) -> int:
        """Revoke the user's active sessions except ``keep_session_id``.

        Runs the ``session.revoke`` hooks and returns how many were revoked.
        """
        return revoke_user_sessions(
            user_id,
            keep_session_id=keep_session_id,
            hooks=self._context.hooks,
            session_storage=self._require_session_storage(),
        )

    def revoke_all_sessions(self, *, user_id: Any) -> int:
        """Revoke all the user's active sessions.

        Runs the ``session.revoke`` hooks and returns how many were revoked.
        """
        return revoke_user_sessions(
            user_id,
            hooks=self._context.hooks,
            session_storage=self._require_session_storage(),
        )

    def sign_in_with_id_token(
        self,
        provider: str,
        id_token: str,
        *,
        user_info: dict[str, Any] | None = None,
        nonce: str | None = None,
        max_age: int | None = None,
        metadata: SessionMetadata | None = None,
    ) -> IdTokenSignIn:
        """Sign in a native/SDK login with a provider ``id_token``.

        The headless sibling of the OAuth callback: Apple's ASAuthorization or
        Google's Credential Manager hand the app a signed id_token, and the
        app posts it to your API (e.g. a GraphQL sign-in mutation). The token
        is validated against the provider's JWKS, then the user is found or
        created by the same core the web callback uses — normalized email
        lookup, the auto-link policy gate, and the accounts-storage signup
        hooks. Then the ``login`` hooks run around a new bearer session whose
        ``login_method`` is ``provider``; ``max_age`` and ``metadata`` are as
        for ``issue_session_token``. Returns the token, the session record, the
        user and whether it was just created.

        Like the browser callback, it refuses (``RuntimeError``) before
        verifying anything when there is no ``session_storage`` or while the
        accounts storage defers its commits, as one that joined an application
        transaction does: the session could outlive a rolled-back user.

        If the identity belongs to an existing social account with
        ``is_login_method=False``, raises ``CrossAuthException`` with
        ``error="access_denied"``. Authenticated connection and linking flows
        still support these accounts; connecting an account does not enable
        it for sign-in.

        ``user_info`` supplies optional display metadata: ``name``,
        ``first_name``, ``last_name``, and ``picture``. Other keys are ignored,
        including when supplied by an ``oauth.id_token`` before hook. Identity
        fields come exclusively from verified provider claims. Apple sends the
        user's name only on the first authorization, and only to the app.
        ``nonce`` is the raw value the app generated for the provider request;
        when given, it must match the
        token's nonce claim (raw or SHA-256 for SDK integrations that send a
        hash). The application must bind the expected nonce to the initiating
        login attempt and prevent reuse; this comparison does not consume it.
        Runs the ``oauth.id_token`` hooks, then the ``login`` hooks.
        """
        session_storage = self._require_session_storage()
        require_committed_accounts(self._context)
        user, created = self.resolve_id_token_user(
            provider, id_token, user_info=user_info, nonce=nonce
        )
        token, record, _ = issue_bearer_session(
            str(user.id),
            hooks=self._context.hooks,
            session_storage=session_storage,
            session_config=self._context.session_config,
            max_age=max_age,
            metadata=metadata,
            login_method=provider,
        )
        return IdTokenSignIn(token, record, user, created)

    def resolve_id_token_user(
        self,
        provider: str,
        id_token: str,
        *,
        user_info: dict[str, Any] | None = None,
        nonce: str | None = None,
    ) -> tuple[User, bool]:
        """Verify a provider ``id_token`` and find or create its user.

        ``sign_in_with_id_token`` without the session, for applications that
        mint their own credential. Returns ``(user, created)`` and runs the
        ``oauth.id_token`` hooks, not the ``login`` hooks. The application owns
        the credential and its commit: with an accounts storage that joins an
        application transaction, the returned records may not be committed
        yet, so commit before issuing a credential for them. ``user_info`` and
        ``nonce`` are as for ``sign_in_with_id_token``.
        """
        resolved_user, _ = _resolve_id_token_user(
            context=self._context,
            providers=self._setup.providers_by_id,
            provider=provider,
            id_token=id_token,
            user_info=user_info,
            nonce=nonce,
        )
        return resolved_user.user, resolved_user.created

    def authenticate(self, email: str, password: str) -> User | None:
        event = self._context.hooks.run_before(
            "authenticate",
            BeforeAuthenticateEvent(email=email, password=password),
        )

        # Normalize at the lookup only: the hook events keep the email exactly
        # as the client submitted it.
        user = authenticate(
            self._context.normalize_email(event.email),
            event.password,
            self._context.accounts_storage,
        )

        self._context.hooks.run_after(
            "authenticate",
            AfterAuthenticateEvent(email=event.email, user=user),
        )

        return user

    @overload
    def before(
        self, event: Literal["authenticate"]
    ) -> _HookDecorator[BeforeAuthenticateEvent, BeforeAuthenticateEvent | None]: ...

    @overload
    def before(
        self, event: Literal["login"]
    ) -> _HookDecorator[BeforeLoginEvent, BeforeLoginEvent | None]: ...

    @overload
    def before(
        self, event: Literal["user.create"]
    ) -> _HookDecorator[BeforeUserCreateEvent, BeforeUserCreateEvent | None]: ...

    @overload
    def before(
        self, event: Literal["social_account.create"]
    ) -> _SocialAccountDecorator[
        BeforeSocialAccountCreateEvent,
        BeforeSocialAccountCreateEvent | None,
        BeforeSocialAccountCreateEvent | BeforeSocialAccountUpdateEvent,
        BeforeSocialAccountCreateEvent | BeforeSocialAccountUpdateEvent | None,
    ]: ...

    @overload
    def before(
        self, event: Literal["social_account.update"]
    ) -> _SocialAccountDecorator[
        BeforeSocialAccountUpdateEvent,
        BeforeSocialAccountUpdateEvent | None,
        BeforeSocialAccountCreateEvent | BeforeSocialAccountUpdateEvent,
        BeforeSocialAccountCreateEvent | BeforeSocialAccountUpdateEvent | None,
    ]: ...

    @overload
    def before(
        self, event: Literal["oauth.id_token"]
    ) -> _HookDecorator[BeforeOAuthIdTokenEvent, BeforeOAuthIdTokenEvent | None]: ...

    @overload
    def before(
        self, event: Literal["logout"]
    ) -> _HookDecorator[BeforeLogoutEvent, BeforeLogoutEvent | None]: ...

    @overload
    def before(
        self, event: Literal["session.revoke"]
    ) -> _HookDecorator[BeforeSessionRevokeEvent, None]: ...

    @overload
    def before(
        self, event: Literal["oauth.authorize"]
    ) -> _HookDecorator[
        BeforeOAuthAuthorizeEvent, BeforeOAuthAuthorizeEvent | None
    ]: ...

    @overload
    def before(
        self, event: Literal["oauth.callback"]
    ) -> _HookDecorator[BeforeOAuthCallbackEvent, BeforeOAuthCallbackEvent | None]: ...

    @overload
    def before(
        self, event: Literal["oauth.link"]
    ) -> _HookDecorator[BeforeOAuthLinkEvent, None]: ...

    @overload
    def before(
        self, event: Literal["oauth.finalize_link"]
    ) -> _HookDecorator[
        BeforeOAuthFinalizeLinkEvent, BeforeOAuthFinalizeLinkEvent | None
    ]: ...

    @overload
    def before(
        self, event: Literal["oauth.disconnect"]
    ) -> _HookDecorator[BeforeOAuthDisconnectEvent, None]: ...

    @overload
    def before(
        self, event: Literal["token.password"]
    ) -> _HookDecorator[BeforeTokenPasswordEvent, None]: ...

    @overload
    def before(
        self, event: Literal["token.authorization_code"]
    ) -> _HookDecorator[BeforeTokenAuthorizationCodeEvent, None]: ...

    def before(
        self, event: HookEventName
    ) -> Callable[[Callable[..., object]], Callable[..., object]]:
        def decorator(handler: Callable[..., object]) -> Callable[..., object]:
            self._context.hooks.register_before(event, handler)
            return handler

        return decorator

    @overload
    def after(
        self, event: Literal["authenticate"]
    ) -> _HookDecorator[AfterAuthenticateEvent, None]: ...

    @overload
    def after(
        self, event: Literal["login"]
    ) -> _HookDecorator[AfterLoginEvent, None]: ...

    @overload
    def after(
        self, event: Literal["user.create"]
    ) -> _HookDecorator[AfterUserCreateEvent, None]: ...

    @overload
    def after(
        self, event: Literal["social_account.create"]
    ) -> _SocialAccountDecorator[
        AfterSocialAccountCreateEvent,
        None,
        AfterSocialAccountCreateEvent | AfterSocialAccountUpdateEvent,
        None,
    ]: ...

    @overload
    def after(
        self, event: Literal["social_account.update"]
    ) -> _SocialAccountDecorator[
        AfterSocialAccountUpdateEvent,
        None,
        AfterSocialAccountCreateEvent | AfterSocialAccountUpdateEvent,
        None,
    ]: ...

    @overload
    def after(
        self, event: Literal["oauth.id_token"]
    ) -> _HookDecorator[AfterOAuthIdTokenEvent, None]: ...

    @overload
    def after(
        self, event: Literal["logout"]
    ) -> _HookDecorator[AfterLogoutEvent, None]: ...

    @overload
    def after(
        self, event: Literal["session.revoke"]
    ) -> _HookDecorator[AfterSessionRevokeEvent, None]: ...

    @overload
    def after(
        self, event: Literal["oauth.authorize"]
    ) -> _HookDecorator[AfterOAuthAuthorizeEvent, None]: ...

    @overload
    def after(
        self, event: Literal["oauth.callback"]
    ) -> _HookDecorator[AfterOAuthCallbackEvent, None]: ...

    @overload
    def after(
        self, event: Literal["oauth.link"]
    ) -> _HookDecorator[AfterOAuthLinkEvent, None]: ...

    @overload
    def after(
        self, event: Literal["oauth.finalize_link"]
    ) -> _HookDecorator[AfterOAuthFinalizeLinkEvent, None]: ...

    @overload
    def after(
        self, event: Literal["oauth.disconnect"]
    ) -> _HookDecorator[AfterOAuthDisconnectEvent, None]: ...

    @overload
    def after(
        self, event: Literal["token.password"]
    ) -> _HookDecorator[AfterTokenPasswordEvent, None]: ...

    @overload
    def after(
        self, event: Literal["token.authorization_code"]
    ) -> _HookDecorator[AfterTokenAuthorizationCodeEvent, None]: ...

    def after(
        self, event: HookEventName
    ) -> Callable[[Callable[..., object]], Callable[..., object]]:
        def decorator(handler: Callable[..., object]) -> Callable[..., object]:
            self._context.hooks.register_after(event, handler)
            return handler

        return decorator

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

    def _apply_hook_response(
        self, source: CrossWebResponse, target: FastAPIResponse
    ) -> None:
        target.status_code = source.status_code

        for name, value in (source.headers or {}).items():
            if name.lower() == "set-cookie":
                continue
            target.headers[name] = value

        for cookie in source.cookies or []:
            set_cookie(target, cookie)

    def issue_session_token(
        self,
        user_id: str,
        *,
        max_age: int | None = None,
        metadata: SessionMetadata | None = None,
        login_method: str | None = None,
    ) -> tuple[str, SessionRecord]:
        """Create a session and return its bearer token with the record.

        For clients that authenticate outside the built-in ``/token`` endpoint
        and outside a browser — a GraphQL sign-in mutation for a native app, a
        CLI. The returned token is the same revocable opaque token ``/token``
        issues: clients send it as ``Authorization: Bearer ...`` and
        ``get_current_user`` resolves it. ``max_age`` overrides the configured
        session lifetime (e.g. longer-lived mobile sessions than browser
        cookies). No cookie is set; the ``login`` hooks run around the
        creation with ``credential="bearer"``, and the raw token is never
        exposed to them. ``login_method`` records how the user signed in, e.g.
        ``"password"`` after ``authenticate()``.
        """
        token, record, _ = issue_bearer_session(
            user_id,
            hooks=self._context.hooks,
            session_storage=self._require_session_storage(),
            session_config=self._context.session_config,
            max_age=max_age,
            metadata=metadata,
            login_method=login_method,
        )
        return token, record

    def login(
        self,
        user_id: str,
        *,
        response: FastAPIResponse,
        metadata: SessionMetadata | None = None,
        login_method: str | None = None,
    ) -> None:
        session_storage = self._require_session_storage()
        hook_response = login_with_session(
            user_id,
            response=self._make_hook_response(response),
            hooks=self._context.hooks,
            session_storage=session_storage,
            session_config=self._context.session_config,
            metadata=metadata,
            login_method=login_method,
        )
        self._apply_hook_response(hook_response, response)

    def logout(
        self,
        request: FastAPIRequest,
        *,
        response: FastAPIResponse,
        scope: LogoutScope = "current",
    ) -> None:
        """Revoke the request's session and clear the session cookie.

        Reads the session cookie, then an ``Authorization: Bearer`` token; the
        mounted ``POST /logout`` route runs the same code. ``scope="all"``
        revokes every session of the session's user (log out everywhere).
        """
        hook_response = logout_session(
            make_http_request(AsyncHTTPRequest.from_fastapi(request)),
            response=self._make_hook_response(response),
            hooks=self._context.hooks,
            session_storage=self._require_session_storage(),
            session_config=self._context.session_config,
            scope=scope,
        )
        self._apply_hook_response(hook_response, response)
