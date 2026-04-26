from __future__ import annotations

import json
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, NamedTuple, cast

from cross_web import AsyncHTTPRequest
from pydantic import BaseModel, HttpUrl, TypeAdapter, ValidationError

from ._context import Context
from ._issuer import AuthorizationCodeGrantData
from ._session import create_session, make_session_cookie, resolve_config
from ._storage import SocialAccount, User
from .exceptions import CrossAuthException
from .hooks import (
    AfterLoginEvent,
    AfterOAuthAuthorizeEvent,
    AfterOAuthCallbackEvent,
    AfterOAuthDisconnectEvent,
    AfterOAuthFinalizeLinkEvent,
    AfterOAuthLinkEvent,
    BeforeLoginEvent,
    BeforeOAuthAuthorizeEvent,
    BeforeOAuthCallbackEvent,
    BeforeOAuthDisconnectEvent,
    BeforeOAuthFinalizeLinkEvent,
    BeforeOAuthLinkEvent,
)
from .social_providers.oauth import (
    OAuth2Exception,
    OAuth2Provider,
    ValidatedUserInfo,
)
from .utils._pkce import (
    calculate_s256_challenge,
    generate_code_verifier,
    validate_pkce,
)
from .utils._response import Response
from .utils._url import construct_relative_url

logger = logging.getLogger(__name__)


# TODO: explain these?
FlowKind = Literal["session", "token", "link", "connect"]


class AuthRequest(BaseModel):
    """Stored state for an in-progress authorization at the provider.

    Keyed by `oauth:authorization_request:{state}` in secondary storage.
    Replaces the pre-refactor OAuth2AuthorizationRequestData.
    """

    flow: FlowKind
    provider_id: str
    state: str
    provider_code_verifier: str | None = None

    # Session + connect flows: where to redirect the user after completion.
    next_url: str | None = None

    # Token flow: the client app's OAuth parameters.
    client_id: str | None = None
    client_redirect_uri: str | None = None
    client_state: str | None = None
    client_code_challenge: str | None = None
    client_code_challenge_method: Literal["S256"] | None = None

    # Link + connect flows: the user who initiated attaching a social account.
    user_id: str | None = None


class LinkCodeData(BaseModel):
    """Stored after a successful link callback; redeemed by finalize-link."""

    expires_at: datetime
    client_id: str
    redirect_uri: str
    code_challenge: str
    code_challenge_method: Literal["S256"]
    user_id: str
    provider_code: str
    provider_code_verifier: str | None = None
    client_state: str | None = None
    provider_callback_extra: dict[str, Any] | None = None


class InitiateLinkRequest(BaseModel):
    redirect_uri: str
    code_challenge: str
    code_challenge_method: Literal["S256"]
    client_id: str
    state: str | None = None


class InitiateLinkResponse(BaseModel):
    authorization_url: str


class DisconnectResponse(BaseModel):
    message: str


class ResolvedUser(NamedTuple):
    user: User
    created: bool


class ResolvedSocialAccount(NamedTuple):
    account: SocialAccount
    created: bool


_AUTH_REQUEST_KEY = "oauth:authorization_request:{state}"
_LINK_CODE_KEY = "oauth:link_request:{code}"
_AUTH_CODE_KEY = "oauth:code:{code}"
_AUTH_CODE_TTL = timedelta(minutes=10)
_LINK_CODE_TTL = timedelta(minutes=10)


def _store_auth_request(context: Context, data: AuthRequest) -> None:
    context.secondary_storage.set(
        _AUTH_REQUEST_KEY.format(state=data.state),
        data.model_dump_json(),
    )


def _load_auth_request(context: Context, state: str) -> AuthRequest | None:
    raw = context.secondary_storage.get(_AUTH_REQUEST_KEY.format(state=state))
    if raw is None:
        return None
    try:
        return AuthRequest.model_validate_json(raw)
    except ValidationError as e:
        logger.error("Invalid stored auth request for state %s: %s", state, e)
        return None


def _generate_provider_pkce(
    provider: OAuth2Provider,
) -> tuple[str | None, str | None, str | None]:
    if not provider.supports_pkce:
        return None, None, None
    verifier = generate_code_verifier()
    return verifier, calculate_s256_challenge(verifier), "S256"


def _proxy_redirect_uri(request: AsyncHTTPRequest, context: Context) -> str:
    return construct_relative_url(str(request.url), "callback", context.base_url)


def _is_safe_next_url(next_url: str) -> bool:
    """Only allow relative paths for `next` to prevent open-redirect."""
    if not next_url.startswith("/"):
        return False
    # Disallow protocol-relative URLs like //evil.com/path
    if next_url.startswith("//"):
        return False
    return True


def _has_alternative_login_method(
    *,
    user: User,
    social_account: SocialAccount,
    social_accounts: list[SocialAccount],
) -> bool:
    # if the current social account isn't a login method, it's always safe to disconnect
    if not social_account.is_login_method:
        return True

    # if the user has a password, they can always disconnect the social account
    if user.has_usable_password:
        return True

    return any(
        not _same_id(account.id, social_account.id) and account.is_login_method
        for account in social_accounts
    )


def _same_id(left: Any, right: Any) -> bool:
    return str(left) == str(right)


async def disconnect_provider(
    provider: OAuth2Provider,
    request: AsyncHTTPRequest,
    context: Context,
) -> Response:
    """DELETE /{provider}/social-accounts[/{social_account_id}] — detach account."""
    if (user := context.get_user_from_request(request)) is None:
        return Response.error(
            "unauthorized",
            error_description="Must be logged in to disconnect a social account",
            status_code=401,
        )

    social_accounts = list(
        context.accounts_storage.list_social_accounts(user_id=user.id)
    )

    if (social_account_id := request.path_params.get("social_account_id")) is None:
        provider_accounts = [
            account for account in social_accounts if account.provider == provider.id
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
        await context.hooks.run_before_async(
            "oauth.disconnect",
            BeforeOAuthDisconnectEvent(
                provider=provider,
                request=request,
                user=user,
                social_account=social_account,
            ),
        )
    except CrossAuthException as e:
        return Response.error(
            e.error,
            error_description=e.error_description,
            status_code=e.status_code,
        )

    if not _has_alternative_login_method(
        user=user,
        social_account=social_account,
        social_accounts=social_accounts,
    ):
        return Response.error(
            "no_alternative_login_method",
            error_description=(
                f"Cannot disconnect {provider.id} because it is your only login method."
            ),
        )

    context.accounts_storage.delete_social_account(social_account.id)

    await context.hooks.run_after_async(
        "oauth.disconnect",
        AfterOAuthDisconnectEvent(
            provider=provider,
            request=request,
            user=user,
            social_account=social_account,
        ),
    )

    return Response(
        status_code=200,
        body=DisconnectResponse(
            message=f"{provider.id} account disconnected"
        ).model_dump_json(),
        headers={"Content-Type": "application/json"},
    )


async def start_session_flow(
    provider: OAuth2Provider,
    request: AsyncHTTPRequest,
    context: Context,
) -> Response:
    """GET /{provider}/login — start a session (cookie) login flow.

    Supports ?next=/some/path (relative path only) to control post-login redirect.
    Falls back to context.default_next_url.
    """
    next_url = request.query_params.get("next") or context.default_next_url
    if not _is_safe_next_url(next_url):
        next_url = context.default_next_url

    state = secrets.token_hex(16)
    verifier, challenge, challenge_method = _generate_provider_pkce(provider)

    _store_auth_request(
        context,
        AuthRequest(
            flow="session",
            provider_id=provider.id,
            state=state,
            provider_code_verifier=verifier,
            next_url=next_url,
        ),
    )

    authorization_url = provider.build_authorization_url(
        state=state,
        redirect_uri=_proxy_redirect_uri(request, context),
        request=request,
        code_challenge=challenge,
        code_challenge_method=challenge_method,
        login_hint=request.query_params.get("login_hint"),
    )

    return Response.redirect(authorization_url)


async def start_connect_flow(
    provider: OAuth2Provider,
    request: AsyncHTTPRequest,
    context: Context,
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

    next_url = request.query_params.get("next") or context.default_next_url
    if not _is_safe_next_url(next_url):
        next_url = context.default_next_url

    state = secrets.token_hex(16)
    verifier, challenge, challenge_method = _generate_provider_pkce(provider)

    _store_auth_request(
        context,
        AuthRequest(
            flow="connect",
            provider_id=provider.id,
            state=state,
            provider_code_verifier=verifier,
            next_url=next_url,
            user_id=str(user.id),
        ),
    )

    authorization_url = provider.build_authorization_url(
        state=state,
        redirect_uri=_proxy_redirect_uri(request, context),
        request=request,
        code_challenge=challenge,
        code_challenge_method=challenge_method,
    )

    return Response.redirect(authorization_url)


async def start_token_flow(
    provider: OAuth2Provider,
    request: AsyncHTTPRequest,
    context: Context,
) -> Response:
    """GET /{provider}/authorize — start an OAuth authorization-code flow for a client app."""

    redirect_uri = request.query_params.get("redirect_uri")

    if not redirect_uri:
        logger.error("No redirect URI provided")
        return Response.error("invalid_request")

    try:
        redirect_uri = str(TypeAdapter(HttpUrl).validate_python(redirect_uri))
    except ValidationError:
        logger.error("Invalid redirect URI")
        return Response.error("invalid_redirect_uri")

    if not context.is_valid_redirect_uri(redirect_uri):
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

    client_id = request.query_params.get("client_id")

    if not client_id:
        return Response.error_redirect(
            redirect_uri,
            error="invalid_request",
            error_description="No client_id provided",
            state=client_state,
        )

    if not context.is_valid_client_id(client_id):
        return Response.error_redirect(
            redirect_uri,
            error="invalid_client",
            error_description="Invalid client_id",
            state=client_state,
        )

    login_hint = request.query_params.get("login_hint")

    authorize_event = BeforeOAuthAuthorizeEvent(
        provider=provider,
        request=request,
        login_hint=login_hint,
    )

    try:
        authorize_event = await context.hooks.run_before_async(
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

    state = secrets.token_hex(16)
    verifier, challenge, challenge_method = _generate_provider_pkce(provider)

    _store_auth_request(
        context,
        AuthRequest(
            flow="token",
            provider_id=provider.id,
            state=state,
            provider_code_verifier=verifier,
            client_id=client_id,
            client_redirect_uri=redirect_uri,
            client_state=client_state,
            client_code_challenge=code_challenge,
            client_code_challenge_method=validated_code_challenge_method,
        ),
    )

    authorization_url = provider.build_authorization_url(
        state=state,
        redirect_uri=_proxy_redirect_uri(request, context),
        request=request,
        code_challenge=challenge,
        code_challenge_method=challenge_method,
        login_hint=authorize_event.login_hint,
    )

    await context.hooks.run_after_async(
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
            state=state,
            authorization_url=authorization_url,
        ),
    )

    return Response.redirect(authorization_url)


async def handle_callback(
    provider: OAuth2Provider,
    request: AsyncHTTPRequest,
    context: Context,
) -> Response:
    """GET/POST /{provider}/callback — provider redirects back here.

    Looks up the stored AuthRequest by state, then dispatches to the flow-specific
    completion: session (cookie + redirect to next_url), token (authorization code
    to client), connect (attach account to current user + redirect), or link
    (stash a link code).

    The provider can short-circuit via `intercept_callback` (for non-OAuth
    callback variants) and post-process the final redirect via
    `finalize_redirect`.
    """
    if intercepted := await provider.intercept_callback(request, context):
        return intercepted

    response = await _handle_oauth_callback(provider, request, context)
    return await provider.finalize_redirect(request, response)


async def _handle_oauth_callback(
    provider: OAuth2Provider,
    request: AsyncHTTPRequest,
    context: Context,
) -> Response:
    """Handle the standard OAuth callback path after provider interception."""
    callback_data = await provider.extract_callback_params(request)
    state = callback_data.state
    auth_request = _load_auth_request(context, state) if state else None

    if callback_data.error:
        logger.error("OAuth error: %s", callback_data.error)
        if auth_request is not None:
            if auth_request.provider_id != provider.id:
                logger.error(
                    "Provider mismatch on callback: expected %s, got %s",
                    auth_request.provider_id,
                    provider.id,
                )
                return Response.error(
                    "server_error", error_description="Provider mismatch"
                )

            return _flow_error(
                auth_request,
                error=callback_data.error,
                error_description=f"Authorization failed: {callback_data.error}",
            )

        return Response.error(
            callback_data.error,
            error_description=f"Authorization failed: {callback_data.error}",
        )

    if not state:
        return Response.error(
            "server_error", error_description="No state found in request"
        )

    if auth_request is None:
        return Response.error(
            "server_error", error_description="Provider data not found"
        )

    if auth_request.provider_id != provider.id:
        logger.error(
            "Provider mismatch on callback: expected %s, got %s",
            auth_request.provider_id,
            provider.id,
        )
        return Response.error("server_error", error_description="Provider mismatch")

    if not callback_data.code:
        return _flow_error(
            auth_request,
            error="server_error",
            error_description="No authorization code received in callback",
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
            token_response, context, callback_data.extra
        )
        validated = provider.validate_user_info(user_info)
    except OAuth2Exception as e:
        return _flow_error(
            auth_request, error=e.error, error_description=e.error_description
        )

    if auth_request.flow in {"session", "token"}:
        callback_event = BeforeOAuthCallbackEvent(
            provider=provider,
            request=request,
            user_info=user_info,
            validated_user_info=validated,
        )
        try:
            callback_event = await context.hooks.run_before_async(
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

        user_info = callback_event.user_info
        validated = callback_event.validated_user_info

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

    try:
        resolved_user, resolved_social_account = resolve_or_create_user(
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

    if auth_request.flow == "session":
        try:
            response = _complete_session(auth_request, resolved_user.user, context)
        except CrossAuthException as e:
            return _flow_error(
                auth_request,
                error=e.error,
                error_description=e.error_description,
                status_code=e.status_code,
            )

        await context.hooks.run_after_async(
            "oauth.callback",
            AfterOAuthCallbackEvent(
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
                    resolved_social_account.account
                    if resolved_social_account.created
                    else None
                ),
                authorization_code=None,
                redirect_uri=None,
                client_state=None,
            ),
        )
        return response

    if auth_request.flow == "token":
        code, response = _complete_token(auth_request, resolved_user.user, context)
        assert auth_request.client_redirect_uri is not None
        await context.hooks.run_after_async(
            "oauth.callback",
            AfterOAuthCallbackEvent(
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
                    resolved_social_account.account
                    if resolved_social_account.created
                    else None
                ),
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
    Session/link flows return a JSON error.
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


def resolve_or_create_user(
    *,
    provider: OAuth2Provider,
    context: Context,
    validated: ValidatedUserInfo,
    user_info: dict[str, Any],
    token_response: Any,
) -> tuple[ResolvedUser, ResolvedSocialAccount]:
    """Find/create a user and social account for this login."""
    social_account = context.accounts_storage.find_social_account(
        provider=provider.id,
        provider_user_id=validated.provider_user_id,
    )

    if social_account:
        social_account = context.accounts_storage.update_social_account(
            social_account.id,
            access_token=token_response.access_token,
            refresh_token=token_response.refresh_token,
            access_token_expires_at=token_response.access_token_expires_at,
            refresh_token_expires_at=token_response.refresh_token_expires_at,
            scope=token_response.scope,
            user_info=user_info,
            provider_email=validated.email,
            provider_email_verified=validated.email_verified,
        )

        user = context.accounts_storage.find_user_by_id(social_account.user_id)

        if user is None:
            raise CrossAuthException(
                "server_error",
                error_description="User not found for social account",
            )

        return (
            ResolvedUser(user=user, created=False),
            ResolvedSocialAccount(account=social_account, created=False),
        )

    if validated.email is None:
        raise CrossAuthException(
            "server_error",
            error_description="No email provided by the identity provider",
        )

    user: User | None = None
    created_user = False

    if provider.can_auto_link(context, validated.email_verified):
        user = context.accounts_storage.find_user_by_email(validated.email)

    if not user:
        existing_user = context.accounts_storage.find_user_by_email(validated.email)
        if existing_user:
            raise CrossAuthException(
                "account_not_linked",
                error_description=(
                    "An account with this email exists but could not be linked "
                    "automatically."
                ),
            )

        if (
            context.config.get("require_verified_email", False)
            and validated.email_verified is not True
        ):
            raise CrossAuthException(
                "email_not_verified",
                error_description=(
                    "Please verify your email with the provider before signing up."
                ),
            )

        user = context.accounts_storage.create_user(
            user_info=user_info,
            email=validated.email,
            email_verified=validated.email_verified or False,
        )
        created_user = True

    created_social_account = context.accounts_storage.create_social_account(
        user_id=user.id,
        provider=provider.id,
        provider_user_id=validated.provider_user_id,
        access_token=token_response.access_token,
        refresh_token=token_response.refresh_token,
        access_token_expires_at=token_response.access_token_expires_at,
        refresh_token_expires_at=token_response.refresh_token_expires_at,
        scope=token_response.scope,
        user_info=user_info,
        provider_email=validated.email,
        provider_email_verified=validated.email_verified,
        is_login_method=True,
    )

    return (
        ResolvedUser(user=user, created=created_user),
        ResolvedSocialAccount(account=created_social_account, created=True),
    )


def _complete_connect(
    *,
    auth_request: AuthRequest,
    provider: OAuth2Provider,
    context: Context,
    validated: ValidatedUserInfo,
    user_info: dict[str, Any],
    token_response: Any,
) -> Response:
    """Attach the provider account to the user who started the connect flow."""
    assert auth_request.user_id is not None

    user = context.accounts_storage.find_user_by_id(auth_request.user_id)
    if user is None:
        raise CrossAuthException(
            "server_error",
            error_description="User from connect flow no longer exists",
        )

    social_account = context.accounts_storage.find_social_account(
        provider=provider.id,
        provider_user_id=validated.provider_user_id,
    )

    if social_account is not None:
        if str(social_account.user_id) != str(user.id):
            raise CrossAuthException(
                "account_already_linked",
                error_description=(
                    "This provider account is already linked to a different user."
                ),
            )

        context.accounts_storage.update_social_account(
            social_account.id,
            access_token=token_response.access_token,
            refresh_token=token_response.refresh_token,
            access_token_expires_at=token_response.access_token_expires_at,
            refresh_token_expires_at=token_response.refresh_token_expires_at,
            scope=token_response.scope,
            user_info=user_info,
            provider_email=validated.email,
            provider_email_verified=validated.email_verified,
        )
    else:
        context.accounts_storage.create_social_account(
            user_id=user.id,
            provider=provider.id,
            provider_user_id=validated.provider_user_id,
            access_token=token_response.access_token,
            refresh_token=token_response.refresh_token,
            access_token_expires_at=token_response.access_token_expires_at,
            refresh_token_expires_at=token_response.refresh_token_expires_at,
            scope=token_response.scope,
            user_info=user_info,
            provider_email=validated.email,
            provider_email_verified=validated.email_verified,
            is_login_method=False,
        )

    next_url = auth_request.next_url or context.default_next_url
    return Response.redirect(next_url)


def _complete_session(
    auth_request: AuthRequest, user: User, context: Context
) -> Response:
    if not context.is_session_enabled:
        return Response.error(
            "server_error",
            error_description="Session flow not configured for this deployment",
        )

    next_url = auth_request.next_url or context.default_next_url
    response = Response.redirect(next_url)

    event = context.hooks.run_before(
        "login",
        BeforeLoginEvent(user_id=str(user.id), response=response),
    )

    resolved = resolve_config(context.session_config)
    session_id, session_data = create_session(
        event.user_id,
        context.secondary_storage,
        max_age=resolved["max_age"],
    )
    cookie = make_session_cookie(session_id, context.session_config)

    if event.response.cookies is None:
        event.response.cookies = []
    event.response.cookies.append(cookie)

    context.hooks.run_after(
        "login",
        AfterLoginEvent(
            user_id=event.user_id,
            response=event.response,
            session_id=session_id,
            session_data=session_data,
            cookie=cookie,
        ),
    )

    return cast(Response, event.response)


def _complete_token(
    auth_request: AuthRequest, user: User, context: Context
) -> tuple[str, Response]:
    # All the token-flow client params must be present at this point — they were
    # validated when we stored the AuthRequest.
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
    )

    context.secondary_storage.set(
        _AUTH_CODE_KEY.format(code=code),
        grant_data.model_dump_json(),
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
        client_id=auth_request.client_id,
        redirect_uri=auth_request.client_redirect_uri,
        code_challenge=auth_request.client_code_challenge,
        code_challenge_method=auth_request.client_code_challenge_method,
        user_id=auth_request.user_id,
        provider_code=provider_code,
        provider_code_verifier=auth_request.provider_code_verifier,
        client_state=auth_request.client_state,
        provider_callback_extra=extra,
    )

    context.secondary_storage.set(
        _LINK_CODE_KEY.format(code=code),
        data.model_dump_json(),
    )

    return Response.redirect(
        auth_request.client_redirect_uri,
        query_params={"link_code": code},
    )


async def start_link_flow(
    provider: OAuth2Provider,
    request: AsyncHTTPRequest,
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
        link_request = InitiateLinkRequest.model_validate_json(await request.get_body())
    except (json.JSONDecodeError, ValidationError) as e:
        logger.error("Invalid request body: %s", e)
        return Response.error(
            "invalid_request", error_description="Invalid request body"
        )

    if not context.is_valid_redirect_uri(link_request.redirect_uri):
        return Response.error(
            "invalid_redirect_uri", error_description="Invalid redirect_uri"
        )

    if not context.is_valid_client_id(link_request.client_id):
        return Response.error("invalid_client", error_description="Invalid client_id")

    try:
        await context.hooks.run_before_async(
            "oauth.link",
            BeforeOAuthLinkEvent(
                provider=provider,
                request=request,
                user=user,
            ),
        )
    except CrossAuthException as e:
        return Response.error(
            e.error,
            error_description=e.error_description,
            status_code=e.status_code,
        )

    state = secrets.token_hex(16)
    verifier, challenge, challenge_method = _generate_provider_pkce(provider)

    _store_auth_request(
        context,
        AuthRequest(
            flow="link",
            provider_id=provider.id,
            state=state,
            provider_code_verifier=verifier,
            client_id=link_request.client_id,
            client_redirect_uri=link_request.redirect_uri,
            client_state=link_request.state,
            client_code_challenge=link_request.code_challenge,
            client_code_challenge_method=link_request.code_challenge_method,
            user_id=str(user.id),
        ),
    )

    authorization_url = provider.build_authorization_url(
        state=state,
        redirect_uri=_proxy_redirect_uri(request, context),
        request=request,
        code_challenge=challenge,
        code_challenge_method=challenge_method,
    )

    await context.hooks.run_after_async(
        "oauth.link",
        AfterOAuthLinkEvent(
            provider=provider,
            request=request,
            user=user,
            link_request=link_request,
            state=state,
            authorization_url=authorization_url,
        ),
    )

    return Response(
        status_code=200,
        body=InitiateLinkResponse(
            authorization_url=authorization_url
        ).model_dump_json(),
        headers={"Content-Type": "application/json"},
    )


async def finalize_link(
    provider: OAuth2Provider,
    request: AsyncHTTPRequest,
    context: Context,
) -> Response:
    """POST /{provider}/finalize-link — client redeems a link_code."""
    user = context.get_user_from_request(request)
    if not user:
        return Response.error(
            "unauthorized", error_description="Not logged in", status_code=401
        )

    try:
        request_data = json.loads(await request.get_body())
    except json.JSONDecodeError as e:
        logger.error("Invalid request body: %s", e)
        return Response.error(
            "invalid_request", error_description="Invalid request body"
        )

    code = request_data.get("link_code")
    allow_login = request_data.get("allow_login", False) is True

    if not code:
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

    if link_data.expires_at < datetime.now(tz=timezone.utc):
        return Response.error("server_error", error_description="Link code has expired")

    if str(user.id) != link_data.user_id:
        return Response.error(
            "unauthorized",
            error_description="Link code does not belong to current user",
            status_code=403,
        )

    if link_data.code_challenge_method != "S256":
        return Response.error(
            "server_error", error_description="Unsupported code challenge method"
        )

    code_verifier = request_data.get("code_verifier")
    if not code_verifier:
        return Response.error(
            "server_error", error_description="No code_verifier provided"
        )

    if not validate_pkce(
        link_data.code_challenge, link_data.code_challenge_method, code_verifier
    ):
        return Response.error(
            "server_error", error_description="Invalid code challenge"
        )

    proxy_redirect_uri = _proxy_redirect_uri(request, context)

    try:
        token_response = provider.exchange_code(
            link_data.provider_code,
            proxy_redirect_uri,
            link_data.provider_code_verifier,
        )
        user_info = provider.fetch_user_info(
            token_response, context, link_data.provider_callback_extra
        )
        validated = provider.validate_user_info(user_info)
    except OAuth2Exception as e:
        return Response.error(e.error, error_description=e.error_description)

    finalize_event = BeforeOAuthFinalizeLinkEvent(
        provider=provider,
        request=request,
        user=user,
        allow_login=allow_login,
        user_info=user_info,
        validated_user_info=validated,
    )
    try:
        finalize_event = await context.hooks.run_before_async(
            "oauth.finalize_link",
            finalize_event,
        )
    except CrossAuthException as e:
        return Response.error(
            e.error,
            error_description=e.error_description,
            status_code=e.status_code,
        )

    allow_login = finalize_event.allow_login
    user_info = finalize_event.user_info
    validated = finalize_event.validated_user_info

    account_linking = context.config.get("account_linking", {})
    if not account_linking.get("enabled", False):
        return Response.error(
            "linking_disabled", error_description="Account linking is not enabled."
        )

    if not provider.trust_email and validated.email_verified is not True:
        return Response.error(
            "email_not_verified",
            error_description="Cannot link account: email not verified by provider.",
        )

    if not provider.allows_different_emails(context, validated.email, user.email):
        return Response.error(
            "email_mismatch",
            error_description="Provider email does not match account email.",
        )

    social_account = context.accounts_storage.find_social_account(
        provider=provider.id,
        provider_user_id=validated.provider_user_id,
    )

    created_social_account: SocialAccount | None = None

    if social_account:
        if social_account.user_id != user.id:
            return Response.error(
                "server_error", error_description="Social account already exists"
            )

        social_account = context.accounts_storage.update_social_account(
            social_account.id,
            access_token=token_response.access_token,
            refresh_token=token_response.refresh_token,
            access_token_expires_at=token_response.access_token_expires_at,
            refresh_token_expires_at=token_response.refresh_token_expires_at,
            scope=token_response.scope,
            user_info=cast(dict[str, Any], user_info),
            provider_email=validated.email,
            provider_email_verified=validated.email_verified,
        )
    else:
        social_account = context.accounts_storage.create_social_account(
            user_id=user.id,
            provider=provider.id,
            provider_user_id=validated.provider_user_id,
            access_token=token_response.access_token,
            refresh_token=token_response.refresh_token,
            access_token_expires_at=token_response.access_token_expires_at,
            refresh_token_expires_at=token_response.refresh_token_expires_at,
            scope=token_response.scope,
            user_info=cast(dict[str, Any], user_info),
            provider_email=validated.email,
            provider_email_verified=validated.email_verified,
            is_login_method=allow_login,
        )
        created_social_account = social_account

    await context.hooks.run_after_async(
        "oauth.finalize_link",
        AfterOAuthFinalizeLinkEvent(
            provider=provider,
            request=request,
            user=user,
            link_data=link_data,
            allow_login=allow_login,
            token_response=token_response,
            user_info=user_info,
            validated_user_info=validated,
            social_account=social_account,
            created_social_account=created_social_account,
        ),
    )

    return Response(status_code=200, body='{"message": "Link finalized"}')
