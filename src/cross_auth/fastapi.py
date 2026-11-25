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
from ._mfa import MFAStatus, RequiresMFA, TotpConfirmation, TotpEnrollment
from ._mfa_flow import (
    MFASession,
    finish_challenge,
)
from ._mfa_flow import confirm_totp_enrollment as _confirm_totp_enrollment
from ._mfa_flow import get_status as _get_mfa_status
from ._mfa_flow import reauthenticate as _reauthenticate
from ._mfa_flow import regenerate_recovery_codes as _regenerate_recovery_codes
from ._mfa_flow import remove_mfa_factor as _remove_mfa_factor
from ._mfa_flow import require_mfa
from ._mfa_flow import start_totp_enrollment as _start_totp_enrollment
from ._login import (
    issue_bearer_session,
    login_with_session,
    logout_session,
    require_immediate_commit,
    revoke_user_session,
    revoke_user_sessions,
)
from ._native import resolve_id_token_user as _resolve_id_token_user
from ._oauth_server import OAuthServer
from ._password import _verify_password, authenticate
from ._request import make_http_request
from ._session import (
    AuthenticatedSession,
    ResolvedSession,
    SessionMetadata,
    UserCanAuthenticate,
    get_user_session,
    make_session_cookie,
    resolve_config,
)
from ._setup import build_auth_setup
from ._storage import (
    AccountsStorage,
    MFAStorage,
    PasswordStorage,
    SecondaryStorage,
    SessionActivityStorage,
    SessionListOrder,
    SessionListResult,
    SessionRecord,
    SessionStatus,
    SessionStorage,
    User,
)
from ._tokens import TokenKind
from .exceptions import CrossAuthException, MFARequired
from .hooks import (
    AfterAuthenticateEvent,
    AfterLoginEvent,
    AfterLogoutEvent,
    AfterMFAChallengeEvent,
    AfterMFAFactorCreateEvent,
    AfterMFAFactorDeleteEvent,
    AfterMFARecoveryCodesRegenerateEvent,
    AfterMFAVerifyEvent,
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
    BeforeMFAFactorCreateEvent,
    BeforeMFAFactorDeleteEvent,
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
        user_can_authenticate: UserCanAuthenticate | None = None,
        mfa_storage: MFAStorage | None = None,
        requires_mfa: RequiresMFA | None = None,
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
            user_can_authenticate=user_can_authenticate,
            mfa_storage=mfa_storage,
            requires_mfa=requires_mfa,
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
        resolution = context.resolve_current_session(request, load_user=True)
        return None if resolution is None else resolution.user

    def _resolve_user(self, request: FastAPIRequest) -> User | None:
        async_request = AsyncHTTPRequest.from_fastapi(request)
        return self._context.get_user_from_request(make_http_request(async_request))

    def get_current_user(self, request: FastAPIRequest) -> User | None:
        """Resolve the current user from the request's session.

        Works both as a FastAPI dependency and called directly (shared-context
        builders, GraphQL resolvers, template helpers). With sliding sessions
        (``update_age``) the stored record refreshes on read; install
        ``SessionCookieMiddleware`` so the rolled cookie also reaches the
        browser. A user ``user_can_authenticate`` refuses resolves to ``None``
        and their session is not refreshed; a ``CrossAuthException`` it raises
        propagates.
        """
        if self._context.get_user_from_request != self._default_get_user_from_request:
            # Preserve the custom-resolver contract: sliding sessions refresh,
            # and sessions record their activity, implicitly before the
            # callback runs, even when the callback uses another
            # authentication mechanism.
            self._queue_session_refresh(request)
            return self._resolve_user(request)

        if self._context.session_storage is None:
            return None
        resolution = self._resolve_session(request, load_user=True)
        return None if resolution is None else resolution.user

    def get_current_session(self, request: FastAPIRequest) -> SessionRecord | None:
        """Resolve the request's session record.

        With ``user_can_authenticate``, a session whose user it refuses counts
        as no session, as for ``get_current_user``.
        """
        resolution = self._resolve_session(request, load_user=False)
        return None if resolution is None else resolution.record

    def _resolve_session(
        self, request: FastAPIRequest, *, load_user: bool
    ) -> ResolvedSession | None:
        self._require_session_storage()
        async_request = AsyncHTTPRequest.from_fastapi(request)
        resolution = self._context.resolve_current_session(
            make_http_request(async_request), load_user=load_user
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
        return resolution

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

        Returns ``None`` when the token is unknown, revoked or expired, when
        the accounts storage does not return its user, or when
        ``user_can_authenticate`` returns False for it; a ``CrossAuthException``
        it raises propagates. Unlike ``get_current_user``, this never calls
        ``get_user_from_request``, so a custom resolver can use it for session
        tokens.

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
        resolved = resolve_config(self._context.session_config)
        records_activity = resolved.get("activity_interval") is not None and isinstance(
            session_storage, SessionActivityStorage
        )
        if resolved.get("update_age") is None and not records_activity:
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
        With two-factor authentication, the user's sign-ins that are waiting
        for their code end too, also when no session was active.
        """
        return revoke_user_sessions(
            user_id,
            keep_session_id=keep_session_id,
            hooks=self._context.hooks,
            session_storage=self._require_session_storage(),
            mfa=self._context.mfa,
        )

    def revoke_all_sessions(self, *, user_id: Any) -> int:
        """Revoke all the user's active sessions.

        Runs the ``session.revoke`` hooks and returns how many were revoked.
        With two-factor authentication, the user's sign-ins that are waiting
        for their code end too, also when no session was active: call it after
        a password reset.
        """
        return revoke_user_sessions(
            user_id,
            hooks=self._context.hooks,
            session_storage=self._require_session_storage(),
            mfa=self._context.mfa,
        )

    def change_password(
        self,
        request: FastAPIRequest,
        *,
        current_password: str | None,
        new_password: str,
        revoke_other_sessions: bool = True,
    ) -> User:
        """Change the password of the request's user and return the updated user.

        The accounts storage must have a ``set_password`` method, as the SQLModel
        one does; with another, this raises ``TypeError``. The user is the one
        the request's session signs in, as for ``require_current_user``;
        without one this raises ``unauthorized`` (401). ``current_password`` must match the user's password, and is
        ``None`` only for a user without one, who sets a first password.
        Otherwise this raises ``invalid_password`` (400) and changes nothing.
        The accounts storage hashes and stores ``new_password``; the SQLModel
        one refuses a password longer than bcrypt's 72 bytes with
        ``password_too_long`` (400).

        Then, with ``revoke_other_sessions``, the user's other sessions are
        revoked through the ``session.revoke`` hooks, with scope ``"others"``,
        and the request's session stays signed in. With two-factor
        authentication, the user's sign-ins that are waiting for their code
        end too: they passed the old password. A hook that refuses raises
        once the password has changed. Revoking needs an accounts storage whose
        writes commit before it returns, as the SQLModel one's do; with one
        that joined an application transaction, this raises ``RuntimeError``
        before changing anything. Check the new password against your own
        rules, such as a minimum length, before calling this.
        """
        session_storage = self._require_session_storage()
        accounts_storage = self._context.accounts_storage
        if not isinstance(accounts_storage, PasswordStorage):
            raise TypeError(
                f"{type(accounts_storage).__name__} cannot change passwords: "
                "it has no set_password method"
            )
        if revoke_other_sessions:
            # Until the new password commits, a login with the old one could
            # start a session that the revocation misses.
            require_immediate_commit(
                accounts_storage.on_commit,
                "change_password cannot revoke the other sessions while the "
                "password change is uncommitted; do not run it inside an "
                "application transaction",
            )
        current = self._resolve_session(request, load_user=True)
        if current is None or current.user is None:
            raise CrossAuthException("unauthorized", "Not logged in", status_code=401)
        user = current.user
        if current_password is None:
            # Only a user without a password may set one without proving it.
            correct = user.hashed_password is None
        else:
            correct = _verify_password(user, current_password)
        if not correct:
            raise CrossAuthException(
                "invalid_password", "The current password is not correct"
            )

        updated = accounts_storage.set_password(user.id, new_password)
        if updated is None:
            raise CrossAuthException("unauthorized", "Not logged in", status_code=401)
        if revoke_other_sessions:
            revoke_user_sessions(
                current.record.user_id,
                keep_session_id=current.record.id,
                hooks=self._context.hooks,
                session_storage=session_storage,
                request=make_http_request(AsyncHTTPRequest.from_fastapi(request)),
                mfa=self._context.mfa,
            )
        return updated

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
        Runs the ``oauth.id_token`` hooks, then the ``login`` hooks. A user
        ``user_can_authenticate`` refuses raises ``CrossAuthException`` once
        the token is verified, before the ``login`` hooks and the session.
        """
        session_storage = self._require_session_storage()
        require_committed_accounts(self._context)
        user, created = self.resolve_id_token_user(
            provider, id_token, user_info=user_info, nonce=nonce
        )
        try:
            token, record, _ = issue_bearer_session(
                str(user.id),
                hooks=self._context.hooks,
                session_storage=session_storage,
                session_config=self._context.session_config,
                # resolve_id_token_user has just checked this user.
                check_user=None,
                max_age=max_age,
                metadata=metadata,
                login_method=provider,
                mfa=self._context.mfa,
            )
        except MFARequired as required:
            raise self._bearer_challenge(required, max_age, metadata) from None
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
        ``nonce`` are as for ``sign_in_with_id_token``. Once the token is
        verified, a user ``user_can_authenticate`` refuses raises
        ``CrossAuthException``, as for ``sign_in_with_id_token``.
        """
        resolved_user, _ = _resolve_id_token_user(
            context=self._context,
            providers=self._setup.providers_by_id,
            provider=provider,
            id_token=id_token,
            user_info=user_info,
            nonce=nonce,
        )
        self._context.check_user_can_authenticate(resolved_user.user)
        return resolved_user.user, resolved_user.created

    def authenticate(self, email: str, password: str) -> User | None:
        """Return the user ``email`` and ``password`` belong to, or ``None``.

        Once the password matches, a user ``user_can_authenticate`` refuses
        raises ``CrossAuthException`` (``access_denied``, or the rule's own
        error) and the ``authenticate`` after hooks do not run. A wrong
        password returns ``None`` without asking the rule.
        """
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
        # Only once the password matched, so a wrong password cannot tell
        # whether the account may sign in.
        if user is not None:
            self._context.check_user_can_authenticate(user)

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

    @overload
    def before(
        self, event: Literal["mfa.factor.create"]
    ) -> _HookDecorator[BeforeMFAFactorCreateEvent, None]: ...

    @overload
    def before(
        self, event: Literal["mfa.factor.delete"]
    ) -> _HookDecorator[BeforeMFAFactorDeleteEvent, None]: ...

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

    @overload
    def after(
        self, event: Literal["mfa.challenge"]
    ) -> _HookDecorator[AfterMFAChallengeEvent, None]: ...

    @overload
    def after(
        self, event: Literal["mfa.verify"]
    ) -> _HookDecorator[AfterMFAVerifyEvent, None]: ...

    @overload
    def after(
        self, event: Literal["mfa.factor.create"]
    ) -> _HookDecorator[AfterMFAFactorCreateEvent, None]: ...

    @overload
    def after(
        self, event: Literal["mfa.factor.delete"]
    ) -> _HookDecorator[AfterMFAFactorDeleteEvent, None]: ...

    @overload
    def after(
        self, event: Literal["mfa.recovery_codes.regenerate"]
    ) -> _HookDecorator[AfterMFARecoveryCodesRegenerateEvent, None]: ...

    def after(
        self, event: HookEventName
    ) -> Callable[[Callable[..., object]], Callable[..., object]]:
        def decorator(handler: Callable[..., object]) -> Callable[..., object]:
            self._context.hooks.register_after(event, handler)
            return handler

        return decorator

    # Two-factor authentication --------------------------------------------

    def _bearer_challenge(
        self,
        required: MFARequired,
        max_age: int | None,
        metadata: SessionMetadata | None,
    ) -> MFARequired:
        return require_mfa(self._context).start_challenge(
            required, kind="bearer", data={"max_age": max_age, "metadata": metadata}
        )

    def _mfa_session(self, request: FastAPIRequest) -> MFASession:
        require_mfa(self._context)
        current = self._resolve_session(request, load_user=True)
        if current is None or current.user is None:
            raise CrossAuthException("unauthorized", "Not logged in", status_code=401)
        return MFASession(
            user=current.user,
            session_id=str(current.record.id),
            signed_in_at=current.record.created_at,
            record=current.record,
            login_method=current.record.login_method,
        )

    def get_mfa_status(self, request: FastAPIRequest) -> MFAStatus:
        """The signed-in user's factors and how many recovery codes are left."""
        return _get_mfa_status(self._context, self._mfa_session(request))

    def get_mfa_status_for(self, user_id: Any) -> MFAStatus:
        """``get_mfa_status`` for any user, such as inside ``requires_mfa``."""
        return require_mfa(self._context).status(user_id)

    def reauthenticate(
        self,
        request: FastAPIRequest,
        *,
        password: str | None = None,
        code: str | None = None,
        recovery_code: str | None = None,
    ) -> datetime:
        """Confirm the signed-in user's identity with exactly one proof.

        Changes to 2FA are then allowed until the returned time
        (``reauthentication_max_age`` after now). A fresh sign-in allows them
        too, so a user who has just signed in need not call this, except in a
        device login's session, whose sign-in proved nothing.
        """
        return _reauthenticate(
            self._context,
            self._mfa_session(request),
            password=password,
            code=code,
            recovery_code=recovery_code,
        )

    def start_totp_enrollment(
        self, request: FastAPIRequest, *, name: str | None = None
    ) -> TotpEnrollment:
        """Start setting up an authenticator app for the signed-in user.

        Needs recent authentication (``reauthentication_required``, 403) and
        a verified email (``email_not_verified``). Nothing is stored for the
        user until ``confirm_totp_enrollment`` checks the first code.
        """
        return _start_totp_enrollment(
            self._context, self._mfa_session(request), name=name
        )

    def confirm_totp_enrollment(
        self,
        request: FastAPIRequest,
        *,
        enrollment_id: str,
        code: str,
        revoke_other_sessions: bool = True,
    ) -> TotpConfirmation:
        """Store the authenticator once ``code`` checks out.

        For a user's first factor this turns 2FA on, returns 10 recovery codes
        (shown once; only hashes are kept) and, with
        ``revoke_other_sessions``, revokes the user's other sessions through
        the ``session.revoke`` hooks.
        """
        from ._mfa_flow import CrossAuthSessions

        return _confirm_totp_enrollment(
            make_http_request(AsyncHTTPRequest.from_fastapi(request)),
            self._context,
            CrossAuthSessions(),
            self._mfa_session(request),
            enrollment_id=enrollment_id,
            code=code,
            revoke_other_sessions=revoke_other_sessions,
        )

    def regenerate_recovery_codes(self, request: FastAPIRequest) -> list[str]:
        """Replace the signed-in user's recovery codes and return the new ones."""
        return _regenerate_recovery_codes(self._context, self._mfa_session(request))

    def remove_mfa_factor(self, request: FastAPIRequest, factor_id: str) -> MFAStatus:
        """Remove one of the signed-in user's factors.

        Removing the last one also deletes the recovery codes: 2FA is off.
        """
        return _remove_mfa_factor(self._context, self._mfa_session(request), factor_id)

    def complete_mfa_login(
        self,
        request: FastAPIRequest,
        challenge: str,
        *,
        response: FastAPIResponse,
        code: str | None = None,
        recovery_code: str | None = None,
    ) -> None:
        """Finish a cookie sign-in ``login`` paused, setting its cookie.

        Give exactly one of ``code`` (from the authenticator app) and
        ``recovery_code``. A wrong code raises ``invalid_code``; the sign-in
        may try again until its attempts run out.
        """
        mfa = require_mfa(self._context)
        pending = mfa.load_challenge(challenge)
        if pending is None or pending.kind not in ("cookie", "browser"):
            raise CrossAuthException(
                "invalid_challenge", "This sign-in has expired; sign in again"
            )
        finished = finish_challenge(
            make_http_request(AsyncHTTPRequest.from_fastapi(request)),
            self._context,
            challenge,
            code=code,
            recovery_code=recovery_code,
        )
        for cookie in finished.response.cookies or []:
            set_cookie(response, cookie)

    def verify_mfa(
        self,
        challenge: str,
        *,
        code: str | None = None,
        recovery_code: str | None = None,
    ) -> tuple[str, SessionRecord]:
        """Finish a bearer sign-in that ``issue_session_token`` or
        ``sign_in_with_id_token`` paused; return its token and record."""
        mfa = require_mfa(self._context)
        pending = mfa.load_challenge(challenge)
        if pending is None or pending.kind != "bearer":
            raise CrossAuthException(
                "invalid_challenge", "This sign-in has expired; sign in again"
            )
        finished = finish_challenge(
            HTTPRequest.from_form_data({}),
            self._context,
            challenge,
            code=code,
            recovery_code=recovery_code,
        )
        assert finished.token is not None and finished.record is not None
        return finished.token, finished.record

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
        mfa_method: str | None = None,
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
        ``"password"`` after ``authenticate()``, or ``"device"`` for a device
        the user approved from a browser where they are signed in, which the
        default 2FA rule does not challenge. A user
        ``user_can_authenticate`` refuses, or one it cannot find, raises
        ``CrossAuthException`` before the ``login`` hooks and creates nothing.

        ``mfa_method`` is the second factor this sign-in has already passed,
        for a ``token_issuer`` that issues sessions with this: pass on its
        ``TokenIssueRequest.mfa_method``, so the session records it and the
        user is not asked for another code. Cross Auth sets that field only
        once it has checked the code. Never pass a value the client sent: it
        would skip the second factor.
        """
        try:
            token, record, _ = issue_bearer_session(
                user_id,
                hooks=self._context.hooks,
                session_storage=self._require_session_storage(),
                session_config=self._context.session_config,
                check_user=self._context.check_user_id_can_authenticate,
                max_age=max_age,
                metadata=metadata,
                login_method=login_method,
                mfa=self._context.mfa,
                mfa_method=mfa_method,
            )
        except MFARequired as required:
            raise self._bearer_challenge(required, max_age, metadata) from None
        return token, record

    def login(
        self,
        user_id: str,
        *,
        response: FastAPIResponse,
        metadata: SessionMetadata | None = None,
        login_method: str | None = None,
    ) -> None:
        """Create a session for ``user_id`` and set its cookie on ``response``.

        Runs the ``login`` hooks with ``credential="cookie"``. A user
        ``user_can_authenticate`` refuses, or one it cannot find, raises
        ``CrossAuthException`` before the hooks and leaves ``response`` as it
        was. With two-factor authentication, a user who needs a second
        factor raises ``MFARequired`` instead, with a ``challenge`` to pass to
        ``complete_mfa_login`` (or post to ``/mfa/verify``); no session is
        created until then.
        """
        session_storage = self._require_session_storage()
        try:
            hook_response = login_with_session(
                user_id,
                response=self._make_hook_response(response),
                hooks=self._context.hooks,
                session_storage=session_storage,
                session_config=self._context.session_config,
                check_user=self._context.check_user_id_can_authenticate,
                metadata=metadata,
                login_method=login_method,
                mfa=self._context.mfa,
            )
        except MFARequired as required:
            mfa = require_mfa(self._context)
            raise mfa.start_challenge(
                required, kind="cookie", data={"metadata": metadata, "next_url": None}
            ) from None
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
            mfa=self._context.mfa,
        )
        self._apply_hook_response(hook_response, response)
