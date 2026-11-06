from __future__ import annotations

import hashlib
import json
import logging
import secrets
from collections.abc import Callable
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any, Literal, cast

from cross_web import HTTPRequest
from pydantic import BaseModel, ValidationError

from ._accounts import (
    ResolvedSocialAccount as ResolvedSocialAccount,
)
from ._accounts import (
    ResolvedUser as ResolvedUser,
)
from ._accounts import (
    VerifiedIdentityGuard,
    _check_login_link_email,
    attach_social_account,
    resolve_user_for_sign_in,
)
from ._accounts import (
    _create_social_account as _create_social_account,
)
from ._accounts import (
    _create_user_with_identity as _create_user_with_identity,
)
from ._accounts import (
    _update_social_account as _update_social_account,
)
from ._accounts import (
    require_committed_accounts as _require_committed_accounts,
)
from ._accounts import (
    resolve_or_create_user as resolve_or_create_user,
)
from ._authorization import (
    _AUTH_REQUEST_KEY,
    _AUTH_REQUEST_TTL,
    _LINK_CODE_KEY,
    _LINK_CODE_TTL,
    ClientAuthorization,
    ConnectAuthorization,
    LinkAuthorization,
    SessionAuthorization,
    TokenAuthorization,
    _binding_cookie,
    _load_auth_request,
    _proxy_redirect_uri,
    begin_authorization,
)
from ._authorization import (
    AuthRequest as AuthRequest,
)
from ._authorization import (
    FlowKind as FlowKind,
)
from ._authorization import (
    InitiateLinkRequest as InitiateLinkRequest,
)
from ._authorization import (
    LinkCodeData as LinkCodeData,
)
from ._authorization_code import (
    AUTH_CODE_KEY as _AUTH_CODE_KEY,
)
from ._authorization_code import (
    AUTH_CODE_TTL as _AUTH_CODE_TTL,
)
from ._authorization_code import (
    AuthorizationCodeGrantData,
)
from ._context import Context
from ._login import (
    BrowserLogin,
    login_with_session,
    logout_session,
    run_now,
)
from ._request import get_header
from ._storage import CommitCallback, User
from .exceptions import CrossAuthException
from .hooks import (
    AfterOAuthAuthorizeEvent,
    AfterOAuthCallbackEvent,
    AfterOAuthDisconnectEvent,
    AfterOAuthFinalizeLinkEvent,
    AfterOAuthLinkEvent,
    BeforeOAuthAuthorizeEvent,
    BeforeOAuthCallbackEvent,
    BeforeOAuthDisconnectEvent,
    BeforeOAuthFinalizeLinkEvent,
    BeforeOAuthLinkEvent,
    LogoutScope,
    ProviderSnapshot,
    SocialAccountSnapshot,
    UserSnapshot,
)
from .models.oauth_token_response import TokenResponse
from .social_providers.oauth import (
    CallbackData,
    OAuth2Exception,
    OAuth2Provider,
    UserInfo,
    ValidatedUserInfo,
)
from .utils._pkce import validate_pkce
from .utils._response import Response

logger = logging.getLogger(__name__)

EXPECTED_OAUTH_CALLBACK_ERRORS = {"access_denied"}


class LogoutRequest(BaseModel):
    scope: LogoutScope = "current"


class InitiateLinkResponse(BaseModel):
    authorization_url: str


class DisconnectResponse(BaseModel):
    message: str


# Called with a callback's verified identity before any account is touched.
OnVerified = Callable[[AuthRequest, ValidatedUserInfo], None]


def _is_safe_next_url(next_url: str) -> bool:
    """Only allow relative paths for `next` to prevent open-redirect."""
    if not next_url.startswith("/"):
        return False
    if next_url.startswith("//"):
        return False
    # Browsers read /\evil.com as //evil.com and drop tabs and newlines.
    if "\\" in next_url or any(ord(char) < 32 or ord(char) == 127 for char in next_url):
        return False
    return True


def _same_id(left: Any, right: Any) -> bool:
    return str(left) == str(right)


def logout(request: HTTPRequest, context: Context) -> Response:
    """POST /logout — revoke the caller's session.

    Body (optional): LogoutRequest (JSON); ``{"scope": "all"}`` revokes every
    session of the caller's user. Always answers 204, also without a session
    to revoke: a client that treats 401 as "sign in again" must not loop on its
    own logout. Only a malformed body or a ``logout`` before hook that raises
    ``CrossAuthException`` changes the status.
    """
    assert context.session_storage is not None
    try:
        logout_request = (
            LogoutRequest.model_validate_json(request.body)
            if request.body
            else LogoutRequest()
        )
    except ValidationError:
        return Response.error(
            "invalid_request", error_description="Invalid request body"
        )

    try:
        response = logout_session(
            request,
            response=Response(status_code=204),
            hooks=context.hooks,
            session_storage=context.session_storage,
            session_config=context.session_config,
            scope=logout_request.scope,
        )
    except CrossAuthException as e:
        return Response.error(
            e.error,
            error_description=e.error_description,
            status_code=e.status_code,
        )
    return cast(Response, response)


def disconnect_provider(
    provider: OAuth2Provider,
    request: HTTPRequest,
    context: Context,
) -> Response:
    """DELETE /{provider}/social-accounts[/{social_account_id}] — detach account."""
    if (user := context.get_user_from_request(request)) is None:
        return Response.error(
            "unauthorized",
            error_description="Must be logged in to disconnect a social account",
            status_code=401,
        )

    if (social_account_id := request.path_params.get("social_account_id")) is None:
        provider_accounts = [
            account
            for account in context.accounts_storage.list_social_accounts(
                user_id=user.id
            )
            if account.provider == provider.id
        ]

        if len(provider_accounts) > 1:
            return Response.error(
                "multiple_accounts_connected",
                error_description=(
                    f"Multiple {provider.id} accounts are connected. "
                    "Provide social_account_id to disconnect one."
                ),
            )

        social_account = provider_accounts[0] if provider_accounts else None
    else:
        social_account = context.accounts_storage.find_social_account_by_id(
            social_account_id
        )

    if (
        social_account is None
        or not _same_id(social_account.user_id, user.id)
        or social_account.provider != provider.id
    ):
        return Response.error(
            "account_not_connected",
            error_description=f"{provider.id} account is not connected",
        )

    try:
        context.hooks.run_before(
            "oauth.disconnect",
            BeforeOAuthDisconnectEvent(
                provider=ProviderSnapshot.of(provider),
                request=request,
                user=UserSnapshot.of(user),
                social_account=SocialAccountSnapshot.of(social_account),
            ),
        )
    except CrossAuthException as e:
        return Response.error(
            e.error,
            error_description=e.error_description,
            status_code=e.status_code,
        )

    result = context.accounts_storage.disconnect_social_account(
        user_id=user.id,
        provider=provider.id,
        social_account_id=social_account.id,
    )
    if result == "not_found":
        return Response.error(
            "account_not_connected",
            error_description=f"{provider.id} account is not connected",
        )
    if result == "last_login_method":
        return Response.error(
            "no_alternative_login_method",
            error_description=(
                f"Cannot disconnect {provider.id} because it is your only login method."
            ),
        )

    disconnect_event = AfterOAuthDisconnectEvent(
        provider=provider,
        request=request,
        user=user,
        social_account=social_account,
    )
    context.accounts_storage.on_commit(
        lambda: context.hooks.run_after("oauth.disconnect", disconnect_event)
    )

    return Response(
        status_code=200,
        body=DisconnectResponse(
            message=f"{provider.id} account disconnected"
        ).model_dump_json(),
        headers={"Content-Type": "application/json"},
    )


def start_session_flow(
    provider: OAuth2Provider,
    request: HTTPRequest,
    context: Context,
    *,
    next_url: str | None = None,
) -> Response:
    """GET /{provider}/login — start a session (cookie) login flow.

    Supports ?next=/some/path (relative path only) to control post-login redirect.
    Framework adapters may pass ``next_url`` instead. Falls back to
    context.default_next_url.
    """
    next_url = next_url or request.query_params.get("next") or context.default_next_url
    if not _is_safe_next_url(next_url):
        next_url = context.default_next_url

    attempt = begin_authorization(
        provider,
        request,
        context,
        SessionAuthorization(
            next_url=next_url, login_hint=request.query_params.get("login_hint")
        ),
    )
    return Response.redirect(
        attempt.authorization_url, cookies=[attempt.binding_cookie]
    )


def start_connect_flow(
    provider: OAuth2Provider,
    request: HTTPRequest,
    context: Context,
    *,
    allow_login: bool = False,
    next_url: str | None = None,
) -> Response:
    """GET /{provider}/connect — logged-in user attaches a social account.

    Unlike the link flow, this is a single round-trip using the session cookie —
    no PKCE round-trip with the client. Requires an authenticated user.

    Supports ?next=/some/path to control post-connect redirect.
    """
    user = context.get_user_from_request(request)
    if user is None:
        return Response.error(
            "unauthorized",
            error_description="Must be logged in to connect a social account",
            status_code=401,
        )

    next_url = next_url or request.query_params.get("next") or context.default_next_url
    if not _is_safe_next_url(next_url):
        next_url = context.default_next_url

    attempt = begin_authorization(
        provider,
        request,
        context,
        ConnectAuthorization(
            user_id=str(user.id), next_url=next_url, allow_login=allow_login
        ),
    )
    return Response.redirect(
        attempt.authorization_url, cookies=[attempt.binding_cookie]
    )


def start_token_flow(
    provider: OAuth2Provider,
    request: HTTPRequest,
    context: Context,
) -> Response:
    """GET /{provider}/authorize — start an OAuth authorization-code flow for a client app."""

    redirect_uri = request.query_params.get("redirect_uri")

    if not redirect_uri:
        logger.error("No redirect URI provided")
        return Response.error("invalid_request")

    client_id = request.query_params.get("client_id")

    if not client_id:
        return Response.error(
            "invalid_request", error_description="No client_id provided"
        )

    client = context.get_client(client_id)
    if client is None:
        return Response.error("invalid_client", error_description="Invalid client_id")

    # Do not normalize the URI or redirect errors until this exact client/URI
    # pair has been checked against the registration.
    if not client.check_redirect_uri(redirect_uri):
        logger.error("Invalid redirect URI")
        return Response.error("invalid_redirect_uri")

    client_state = request.query_params.get("state")
    response_type = request.query_params.get("response_type")

    if not response_type:
        return Response.error_redirect(
            redirect_uri,
            error="invalid_request",
            error_description="No response type provided",
            state=client_state,
        )

    if response_type != "code":
        return Response.error_redirect(
            redirect_uri,
            error="invalid_request",
            error_description="Unsupported response type",
            state=client_state,
        )

    code_challenge = request.query_params.get("code_challenge")
    code_challenge_method = request.query_params.get("code_challenge_method")

    if not code_challenge:
        return Response.error_redirect(
            redirect_uri,
            error="invalid_request",
            error_description="No code challenge provided",
            state=client_state,
        )

    if code_challenge_method != "S256":
        return Response.error_redirect(
            redirect_uri,
            error="invalid_request",
            error_description="Unsupported code challenge method",
            state=client_state,
        )

    validated_code_challenge_method = cast(Literal["S256"], code_challenge_method)

    login_hint = request.query_params.get("login_hint")

    authorize_event = BeforeOAuthAuthorizeEvent(
        provider=ProviderSnapshot.of(provider),
        request=request,
        login_hint=login_hint,
    )

    try:
        authorize_event = context.hooks.run_before(
            "oauth.authorize",
            authorize_event,
        )
    except CrossAuthException as e:
        return Response.error_redirect(
            redirect_uri,
            error=e.error,
            error_description=e.error_description,
            state=client_state,
        )

    attempt = begin_authorization(
        provider,
        request,
        context,
        TokenAuthorization(
            client=ClientAuthorization(
                client_id=client_id,
                redirect_uri=redirect_uri,
                state=client_state,
                code_challenge=code_challenge,
                code_challenge_method=validated_code_challenge_method,
            ),
            login_hint=authorize_event.login_hint,
        ),
    )

    context.hooks.run_after(
        "oauth.authorize",
        AfterOAuthAuthorizeEvent(
            provider=provider,
            request=request,
            redirect_uri=redirect_uri,
            client_id=client_id,
            client_state=client_state,
            login_hint=authorize_event.login_hint,
            code_challenge=code_challenge,
            code_challenge_method=validated_code_challenge_method,
            state=attempt.data.state,
            authorization_url=attempt.authorization_url,
        ),
    )

    return Response.redirect(
        attempt.authorization_url, cookies=[attempt.binding_cookie]
    )


def handle_callback(
    provider: OAuth2Provider,
    request: HTTPRequest,
    context: Context,
    *,
    login: BrowserLogin | None = None,
    on_verified: OnVerified | None = None,
) -> Response:
    """GET/POST /{provider}/callback — provider redirects back here.

    Looks up the stored AuthRequest by state, then dispatches to the flow-specific
    completion: session (cookie + redirect to next_url), token (authorization code
    to client), connect (attach account to current user + redirect), or link
    (stash a link code).

    The provider can short-circuit via `intercept_callback` (for non-OAuth
    callback variants) and post-process the final redirect via
    `finalize_redirect`.

    The callback is a top-level browser navigation, so when the stored
    AuthRequest is missing or expired (and no flow-specific redirect target is
    known) errors redirect to `default_next_url` instead of returning a JSON
    body that would strand the user on the API origin. `default_next_url` is
    operator configuration fixed at construction time — never derived from the
    request — so these fallback redirects cannot be attacker-controlled.

    Session sign-ins use ``login`` when a framework owns the browser session,
    and a Cross Auth cookie session otherwise. ``on_verified`` lets a framework
    adapter refuse a session or connect callback once the provider identity is
    verified and before any account is looked up or written; its exceptions
    propagate.
    """
    if intercepted := provider.intercept_callback(request, context):
        return intercepted

    response = _handle_oauth_callback(
        provider, request, context, login=login, on_verified=on_verified
    )
    return provider.finalize_redirect(request, response)


def _redirect_callback_to_get(
    request: HTTPRequest,
    context: Context,
    callback_data: CallbackData,
) -> Response:
    """Resume a form-post callback with the browser's SameSite=Lax cookie.

    Cross-site POSTs omit that cookie. Store the callback payload temporarily
    and redirect with 303 so the browser follows with a GET. Only the opaque
    resume token enters the URL; provider codes and profile data stay in storage.
    """
    resume = secrets.token_urlsafe(32)
    context.secondary_storage.set(
        f"oauth:form_post:{resume}",
        callback_data.model_dump_json(),
        ttl=int(_AUTH_REQUEST_TTL.total_seconds()),
    )
    response = Response.redirect(
        _proxy_redirect_uri(request, context),
        query_params={"resume": resume},
        headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"},
    )
    response.status_code = 303
    return response


def _handle_oauth_callback(
    provider: OAuth2Provider,
    request: HTTPRequest,
    context: Context,
    *,
    login: BrowserLogin | None,
    on_verified: OnVerified | None,
) -> Response:
    """Handle the standard OAuth callback path after provider interception."""
    resume = request.query_params.get("resume") if request.method == "GET" else None
    if resume:
        raw = context.secondary_storage.get(f"oauth:form_post:{resume}")
        if raw is None:
            return Response.error(
                "invalid_request", "Callback continuation has expired"
            )
        try:
            callback_data = CallbackData.model_validate_json(raw)
        except ValidationError:
            return Response.error("invalid_request", "Invalid callback continuation")
    else:
        callback_data = provider.extract_callback_params(request)

    state = callback_data.state
    auth_request = _load_auth_request(context, state) if state else None
    if auth_request is None:
        return _complete_oauth_callback(
            provider,
            request,
            context,
            callback_data,
            None,
            login=login,
            on_verified=on_verified,
        )

    if auth_request.provider_id != provider.id:
        return Response.error("server_error", "Provider mismatch")

    if request.method == "POST":
        return _redirect_callback_to_get(request, context, callback_data)

    cookie = _binding_cookie(request, context, auth_request.state, "", max_age=0)
    binding = request.cookies.get(cookie.name)
    if not binding or not secrets.compare_digest(
        hashlib.sha256(binding.encode()).hexdigest(), auth_request.browser_binding
    ):
        return Response.error(
            "invalid_request", "OAuth callback belongs to another browser"
        )

    if auth_request.flow in {"connect", "link"}:
        user = context.get_user_from_request(request)
        # Bearer-only link clients authenticate again at finalize-link, since
        # the provider's browser redirect cannot carry their bearer header.
        if (user is None and auth_request.flow == "connect") or (
            user is not None and not _same_id(user.id, auth_request.user_id)
        ):
            return Response.error(
                "access_denied", "The account-linking user has changed", status_code=403
            )

    if resume and context.secondary_storage.pop(f"oauth:form_post:{resume}") is None:
        return Response.error(
            "invalid_request", "Callback continuation has already been used"
        )

    # Validate before consuming: a wrong browser/provider cannot cancel a valid
    # attempt. Atomic pop lets only one concurrent callback complete it.
    raw = context.secondary_storage.pop(
        _AUTH_REQUEST_KEY.format(state=auth_request.state)
    )
    if raw is None:
        return Response.error("invalid_request", "OAuth callback has already been used")

    response = _complete_oauth_callback(
        provider,
        request,
        context,
        callback_data,
        auth_request,
        login=login,
        on_verified=on_verified,
    )
    response.cookies = [*(response.cookies or []), cookie]
    return response


def _complete_oauth_callback(
    provider: OAuth2Provider,
    request: HTTPRequest,
    context: Context,
    callback_data: CallbackData,
    auth_request: AuthRequest | None,
    *,
    login: BrowserLogin | None,
    on_verified: OnVerified | None,
) -> Response:
    if auth_request is not None and auth_request.flow in {"token", "link"}:
        # Started before the OAuth server was removed: the callback stays mounted
        # for session and connect flows, so refuse here, before the provider
        # code is exchanged and without redirecting to the client's URI.
        if context.oauth_server is None:
            return Response.error("invalid_request", "The OAuth server is disabled")
        if (
            auth_request.client_id is None
            or auth_request.client_redirect_uri is None
            or not context.is_valid_redirect_uri(
                auth_request.client_redirect_uri, client_id=auth_request.client_id
            )
        ):
            return Response.error(
                "invalid_redirect_uri",
                "Callback is no longer registered for this client",
            )

    state = callback_data.state
    if callback_data.error:
        level = (
            logging.INFO
            if callback_data.error in EXPECTED_OAUTH_CALLBACK_ERRORS
            else logging.ERROR
        )
        logger.log(level, "OAuth error: %s", callback_data.error)
        if auth_request is not None:
            return _flow_error(
                auth_request,
                error=callback_data.error,
                error_description=f"Authorization failed: {callback_data.error}",
            )

        return Response.error_redirect(
            context.default_next_url,
            error=callback_data.error,
            error_description=f"Authorization failed: {callback_data.error}",
        )

    if not state:
        return Response.error_redirect(
            context.default_next_url,
            error="invalid_request",
            error_description="No state found in request",
        )

    if auth_request is None:
        return Response.error_redirect(
            context.default_next_url,
            error="session_expired",
            error_description="The authorization request has expired. Please try again.",
        )

    if not callback_data.code:
        return _flow_error(
            auth_request,
            error="server_error",
            error_description="No authorization code received in callback",
        )

    try:
        provider.validate_auth_request(auth_request)
    except OAuth2Exception as e:
        return _flow_error(
            auth_request, error=e.error, error_description=e.error_description
        )

    if auth_request.flow == "link":
        return _complete_link(
            auth_request, callback_data.code, callback_data.extra, context
        )

    try:
        token_response = provider.exchange_code(
            callback_data.code,
            _proxy_redirect_uri(request, context),
            auth_request.provider_code_verifier,
        )

        user_info = provider.fetch_user_info(
            token_response,
            context,
            callback_data.extra,
            provider_data=auth_request.provider_data,
        )

        validated = provider.validate_user_info(user_info)
    except OAuth2Exception as e:
        return _flow_error(
            auth_request, error=e.error, error_description=e.error_description
        )

    if on_verified is not None:
        on_verified(auth_request, validated)

    if auth_request.flow == "connect":
        try:
            return _complete_connect(
                auth_request=auth_request,
                provider=provider,
                context=context,
                validated=validated,
                user_info=cast(dict[str, Any], user_info),
                token_response=token_response,
            )
        except CrossAuthException as e:
            return _flow_error(
                auth_request, error=e.error, error_description=e.error_description
            )

    if auth_request.flow in {"session", "token"}:
        return _complete_sign_in(
            auth_request=auth_request,
            provider=provider,
            request=request,
            context=context,
            callback_data=callback_data,
            token_response=token_response,
            user_info=user_info,
            validated=validated,
            login=login,
        )

    return Response.error("server_error", error_description="Unknown flow")


def _complete_sign_in(
    *,
    auth_request: AuthRequest,
    provider: OAuth2Provider,
    request: HTTPRequest,
    context: Context,
    callback_data: CallbackData,
    token_response: TokenResponse,
    user_info: UserInfo,
    validated: ValidatedUserInfo,
    login: BrowserLogin | None,
) -> Response:
    """Check login eligibility and complete a session or token sign-in."""
    identity_guard = VerifiedIdentityGuard.of(provider, validated, user_info)
    provider_snapshot = identity_guard.provider
    callback_event = BeforeOAuthCallbackEvent(
        provider=provider_snapshot,
        request=request,
        user_info=user_info,
        validated_user_info=validated,
    )

    try:
        callback_event = context.hooks.run_before(
            "oauth.callback",
            callback_event,
        )
    except CrossAuthException as e:
        return _flow_error(
            auth_request,
            error=e.error,
            error_description=e.error_description,
            status_code=e.status_code,
        )

    identity_guard.check("oauth.callback", callback_event)
    user_info = callback_event.user_info

    try:
        resolved_user, resolved_social_account = resolve_user_for_sign_in(
            provider=provider,
            context=context,
            validated=validated,
            user_info=cast(dict[str, Any], user_info),
            token_response=token_response,
        )
    except CrossAuthException as e:
        return _flow_error(
            auth_request, error=e.error, error_description=e.error_description
        )

    _require_committed_accounts(context)

    after_event = AfterOAuthCallbackEvent(
        provider=provider,
        request=request,
        auth_request=auth_request,
        callback_data=callback_data,
        token_response=token_response,
        user_info=user_info,
        validated_user_info=validated,
        user=resolved_user.user,
        social_account=resolved_social_account.account,
        created_user=resolved_user.user if resolved_user.created else None,
        created_social_account=(
            resolved_social_account.account if resolved_social_account.created else None
        ),
        authorization_code=None,
        redirect_uri=None,
        client_state=None,
    )

    if auth_request.flow == "session":
        try:
            response, on_commit = _complete_session(
                auth_request,
                resolved_user.user,
                context,
                request,
                login=login,
            )
        except CrossAuthException as e:
            return _flow_error(
                auth_request,
                error=e.error,
                error_description=e.error_description,
                status_code=e.status_code,
            )

        on_commit(lambda: context.hooks.run_after("oauth.callback", after_event))

        return response

    if auth_request.flow == "token":
        code, response = _complete_token(auth_request, resolved_user.user, context)
        assert auth_request.client_redirect_uri is not None

        # Account changes are committed (checked above) and secondary storage
        # has no transactions, so the code is already durable.
        context.hooks.run_after(
            "oauth.callback",
            replace(
                after_event,
                authorization_code=code,
                redirect_uri=auth_request.client_redirect_uri,
                client_state=auth_request.client_state,
            ),
        )

        return response

    return Response.error("server_error", error_description="Unknown flow")


def _flow_error(
    auth_request: AuthRequest,
    *,
    error: str,
    error_description: str | None,
    status_code: int = 400,
) -> Response:
    """Render an error in a way appropriate to the flow.

    Token flow redirects to client with error params (so the client sees it).
    Session/link/connect flows return a JSON error.
    """
    if auth_request.flow == "token" and auth_request.client_redirect_uri:
        return Response.error_redirect(
            auth_request.client_redirect_uri,
            error=error,
            error_description=error_description,
            state=auth_request.client_state,
        )

    return Response.error(
        error,
        error_description=error_description,
        status_code=status_code,
    )


def _complete_connect(
    *,
    auth_request: AuthRequest,
    provider: OAuth2Provider,
    context: Context,
    validated: ValidatedUserInfo,
    user_info: dict[str, Any],
    token_response: TokenResponse,
) -> Response:
    """Attach the provider account to the user who started the connect flow."""
    assert auth_request.user_id is not None

    user = context.accounts_storage.find_user_by_id(auth_request.user_id)
    if user is None:
        raise CrossAuthException(
            "server_error",
            error_description="User from connect flow no longer exists",
        )

    if auth_request.allow_login:
        _check_login_link_email(provider, context, validated, user)

    attach_social_account(
        provider=provider,
        context=context,
        user=user,
        validated=validated,
        user_info=user_info,
        token_response=token_response,
        allow_login=auth_request.allow_login,
    )

    next_url = auth_request.next_url or context.default_next_url
    return Response.redirect(next_url)


def _complete_session(
    auth_request: AuthRequest,
    user: User,
    context: Context,
    request: HTTPRequest,
    *,
    login: BrowserLogin | None,
) -> tuple[Response, Callable[[CommitCallback], None]]:
    next_url = auth_request.next_url or context.default_next_url
    if login is not None:
        on_commit = login.on_commit
        response = cast(
            Response,
            login.login(
                user,
                response=Response.redirect(next_url),
                login_method=auth_request.provider_id,
            ),
        )
        return response, on_commit

    session_storage = context.session_storage
    if not context.cookie_auth_enabled:
        response = Response.error(
            "server_error",
            error_description=(
                "Cookie auth is not enabled for this deployment "
                "(config['session']['cookies']['auth'])"
            ),
        )
        return (
            response,
            run_now if session_storage is None else session_storage.on_commit,
        )

    if session_storage is None:
        raise RuntimeError("Session flow not configured for this deployment")

    response = login_with_session(
        str(user.id),
        response=Response.redirect(next_url),
        hooks=context.hooks,
        session_storage=session_storage,
        session_config=context.session_config,
        metadata={"user_agent": get_header(request.headers, "user-agent")},
        login_method=auth_request.provider_id,
    )
    return cast(Response, response), session_storage.on_commit


def _complete_token(
    auth_request: AuthRequest, user: User, context: Context
) -> tuple[str, Response]:
    assert auth_request.client_id is not None
    assert auth_request.client_redirect_uri is not None
    assert auth_request.client_code_challenge is not None
    assert auth_request.client_code_challenge_method is not None

    code = secrets.token_urlsafe(32)

    grant_data = AuthorizationCodeGrantData(
        user_id=str(user.id),
        expires_at=datetime.now(tz=timezone.utc) + _AUTH_CODE_TTL,
        client_id=auth_request.client_id,
        redirect_uri=auth_request.client_redirect_uri,
        code_challenge=auth_request.client_code_challenge,
        code_challenge_method=auth_request.client_code_challenge_method,
        login_method=auth_request.provider_id,
    )

    context.secondary_storage.set(
        _AUTH_CODE_KEY.format(code=code),
        grant_data.model_dump_json(),
        ttl=int(_AUTH_CODE_TTL.total_seconds()),
    )

    query_params: dict[str, str] = {"code": code}
    if auth_request.client_state:
        query_params["state"] = auth_request.client_state

    return code, Response.redirect(
        auth_request.client_redirect_uri,
        query_params=query_params,
    )


def _complete_link(
    auth_request: AuthRequest,
    provider_code: str,
    extra: dict[str, Any] | None,
    context: Context,
) -> Response:
    assert auth_request.user_id is not None
    assert auth_request.client_id is not None
    assert auth_request.client_redirect_uri is not None
    assert auth_request.client_code_challenge is not None
    assert auth_request.client_code_challenge_method is not None

    code = secrets.token_urlsafe(32)

    data = LinkCodeData(
        expires_at=datetime.now(tz=timezone.utc) + _LINK_CODE_TTL,
        provider_id=auth_request.provider_id,
        client_id=auth_request.client_id,
        redirect_uri=auth_request.client_redirect_uri,
        code_challenge=auth_request.client_code_challenge,
        code_challenge_method=auth_request.client_code_challenge_method,
        user_id=auth_request.user_id,
        provider_code=provider_code,
        provider_code_verifier=auth_request.provider_code_verifier,
        provider_data=auth_request.provider_data,
        client_state=auth_request.client_state,
        provider_callback_extra=extra,
    )

    context.secondary_storage.set(
        _LINK_CODE_KEY.format(code=code),
        data.model_dump_json(),
        ttl=int(_LINK_CODE_TTL.total_seconds()),
    )

    return Response.redirect(
        auth_request.client_redirect_uri,
        query_params={"link_code": code},
    )


def start_link_flow(
    provider: OAuth2Provider,
    request: HTTPRequest,
    context: Context,
) -> Response:
    """POST /{provider}/link — logged-in user starts an account-linking flow.

    Body: InitiateLinkRequest (JSON). Returns 200 with authorization URL.
    """
    user = context.get_user_from_request(request)
    if not user:
        return Response.error(
            "unauthorized",
            error_description="User must be authenticated to initiate link flow",
            status_code=401,
        )

    account_linking = context.config.get("account_linking", {})
    if not account_linking.get("enabled", False):
        return Response.error(
            "linking_disabled",
            error_description="Account linking is not enabled",
        )

    try:
        link_request = InitiateLinkRequest.model_validate_json(request.body)
    except ValidationError as e:
        logger.error("Invalid request body: %s", e)
        return Response.error(
            "invalid_request", error_description="Invalid request body"
        )

    client = context.get_client(link_request.client_id)
    if client is None:
        return Response.error("invalid_client", error_description="Invalid client_id")

    if not client.check_redirect_uri(link_request.redirect_uri):
        return Response.error(
            "invalid_redirect_uri", error_description="Invalid redirect_uri"
        )

    try:
        context.hooks.run_before(
            "oauth.link",
            BeforeOAuthLinkEvent(
                provider=ProviderSnapshot.of(provider),
                request=request,
                user=UserSnapshot.of(user),
            ),
        )
    except CrossAuthException as e:
        return Response.error(
            e.error,
            error_description=e.error_description,
            status_code=e.status_code,
        )

    attempt = begin_authorization(
        provider,
        request,
        context,
        LinkAuthorization(
            user_id=str(user.id),
            client=ClientAuthorization(
                client_id=link_request.client_id,
                redirect_uri=link_request.redirect_uri,
                state=link_request.state,
                code_challenge=link_request.code_challenge,
                code_challenge_method=link_request.code_challenge_method,
            ),
        ),
    )

    context.hooks.run_after(
        "oauth.link",
        AfterOAuthLinkEvent(
            provider=provider,
            request=request,
            user=user,
            link_request=link_request,
            state=attempt.data.state,
            authorization_url=attempt.authorization_url,
        ),
    )

    return Response(
        status_code=200,
        cookies=[attempt.binding_cookie],
        body=InitiateLinkResponse(
            authorization_url=attempt.authorization_url
        ).model_dump_json(),
        headers={"Content-Type": "application/json"},
    )


def finalize_link(
    provider: OAuth2Provider,
    request: HTTPRequest,
    context: Context,
) -> Response:
    """POST /{provider}/finalize-link — client redeems a link_code."""
    user = context.get_user_from_request(request)
    if not user:
        return Response.error(
            "unauthorized", error_description="Not logged in", status_code=401
        )

    try:
        request_data = json.loads(request.body)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        logger.error("Invalid request body: %s", e)
        return Response.error(
            "invalid_request", error_description="Invalid request body"
        )

    if not isinstance(request_data, dict):
        return Response.error("invalid_request", "Request body must be an object")

    code = request_data.get("link_code")
    allow_login = request_data.get("allow_login", False) is True

    if not isinstance(code, str) or not code:
        return Response.error(
            "server_error", error_description="No link code found in request"
        )

    raw = context.secondary_storage.get(_LINK_CODE_KEY.format(code=code))
    if not raw:
        return Response.error(
            "server_error", error_description="No link data found in secondary storage"
        )

    try:
        link_data = LinkCodeData.model_validate_json(raw)
    except ValidationError as e:
        logger.error("Invalid link data", exc_info=e)
        return Response.error("server_error", error_description="Invalid link data")

    if link_data.provider_id != provider.id:
        return Response.error(
            "invalid_request", "Link provider mismatch; restart linking"
        )

    if link_data.expires_at <= datetime.now(tz=timezone.utc):
        return Response.error("server_error", error_description="Link code has expired")

    if str(user.id) != link_data.user_id:
        return Response.error(
            "unauthorized",
            error_description="Link code does not belong to current user",
            status_code=403,
        )

    client = context.get_client(link_data.client_id)
    if client is None:
        return Response.error("invalid_client", "Invalid client_id")

    if not client.check_redirect_uri(link_data.redirect_uri):
        return Response.error("invalid_redirect_uri", "Invalid redirect_uri")

    code_verifier = request_data.get("code_verifier")
    if not isinstance(code_verifier, str) or not code_verifier:
        return Response.error(
            "server_error", error_description="No code_verifier provided"
        )

    if not validate_pkce(
        link_data.code_challenge, link_data.code_challenge_method, code_verifier
    ):
        return Response.error(
            "server_error", error_description="Invalid code challenge"
        )

    try:
        provider.validate_link_data(link_data)
    except OAuth2Exception as e:
        return Response.error(e.error, error_description=e.error_description)

    if context.secondary_storage.pop(_LINK_CODE_KEY.format(code=code)) is None:
        return Response.error("invalid_request", "Link code has already been used")

    if link_data.expires_at <= datetime.now(tz=timezone.utc):
        return Response.error("server_error", error_description="Link code has expired")

    proxy_redirect_uri = _proxy_redirect_uri(request, context)

    try:
        token_response = provider.exchange_code(
            link_data.provider_code,
            proxy_redirect_uri,
            link_data.provider_code_verifier,
        )
        user_info = provider.fetch_user_info(
            token_response,
            context,
            link_data.provider_callback_extra,
            provider_data=link_data.provider_data,
        )
        validated = provider.validate_user_info(user_info)
    except OAuth2Exception as e:
        return Response.error(e.error, error_description=e.error_description)

    identity_guard = VerifiedIdentityGuard.of(provider, validated, user_info)
    provider_snapshot = identity_guard.provider
    user_snapshot = UserSnapshot.of(user)
    finalize_event = BeforeOAuthFinalizeLinkEvent(
        provider=provider_snapshot,
        request=request,
        user=user_snapshot,
        allow_login=allow_login,
        user_info=user_info,
        validated_user_info=validated,
    )
    try:
        finalize_event = context.hooks.run_before(
            "oauth.finalize_link",
            finalize_event,
        )
    except CrossAuthException as e:
        return Response.error(
            e.error,
            error_description=e.error_description,
            status_code=e.status_code,
        )

    if finalize_event.user != user_snapshot:
        raise ValueError("oauth.finalize_link before hooks cannot change the user")
    identity_guard.check("oauth.finalize_link", finalize_event)
    allow_login = finalize_event.allow_login
    user_info = finalize_event.user_info

    account_linking = context.config.get("account_linking", {})
    if not account_linking.get("enabled", False):
        return Response.error(
            "linking_disabled", error_description="Account linking is not enabled."
        )

    try:
        _check_login_link_email(provider, context, validated, user)
    except CrossAuthException as e:
        return Response.error(e.error, error_description=e.error_description)

    try:
        resolved_account = attach_social_account(
            provider=provider,
            context=context,
            user=user,
            validated=validated,
            user_info=cast(dict[str, Any], user_info),
            token_response=token_response,
            allow_login=allow_login,
        )
    except CrossAuthException as exc:
        return Response.error(
            exc.error,
            error_description=exc.error_description,
            status_code=exc.status_code,
        )

    after_event = AfterOAuthFinalizeLinkEvent(
        provider=provider,
        request=request,
        user=user,
        link_data=link_data,
        allow_login=allow_login,
        token_response=token_response,
        user_info=user_info,
        validated_user_info=validated,
        social_account=resolved_account.account,
        created_social_account=(
            resolved_account.account if resolved_account.created else None
        ),
    )
    context.accounts_storage.on_commit(
        lambda: context.hooks.run_after("oauth.finalize_link", after_event)
    )

    return Response(status_code=200, body='{"message": "Link finalized"}')
