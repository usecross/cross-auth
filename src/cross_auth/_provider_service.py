"""Shared provider-flow helpers.

These helpers are extracted so that AuthCompletion implementations can reuse
the same pipeline without going through HTTP-handler methods on the provider
class.

Three concerns live here:
- state generation and persistence (prepare_authorization)
- callback parsing against persisted state (parse_callback_and_load_state)
- provider token exchange + local user resolution (exchange_and_resolve_user)

Each function raises OAuth2Exception on failure; callers decide how to
render the error.
"""

from __future__ import annotations

import logging
import secrets
from typing import Any, cast

from cross_web import AsyncHTTPRequest
from pydantic import ValidationError

from ._completion import AuthFlowState, ProviderAuthResult
from ._context import Context
from ._storage import SocialAccount, User
from .exceptions import CrossAuthException
from .social_providers.oauth import (
    CallbackData,
    OAuth2Exception,
    OAuth2Provider,
)
from .utils._pkce import calculate_s256_challenge, generate_code_verifier
from .utils._url import construct_relative_url

logger = logging.getLogger(__name__)

_STATE_KEY_PREFIX = "oauth:authorization_request:"


def build_proxy_redirect_uri(request: AsyncHTTPRequest, base_url: str | None) -> str:
    """The provider-facing callback URL the library advertises to the provider."""
    return construct_relative_url(str(request.url), "callback", base_url)


def generate_provider_pkce(
    provider: OAuth2Provider,
) -> tuple[str | None, str | None, str | None]:
    """Generate a PKCE verifier/challenge pair for the provider leg, if supported."""
    if not provider.supports_pkce:
        return None, None, None
    verifier = generate_code_verifier()
    challenge = calculate_s256_challenge(verifier)
    return verifier, challenge, "S256"


def prepare_authorization(
    provider: OAuth2Provider,
    request: AsyncHTTPRequest,
    context: Context,
    *,
    kind: str,
    completion_state: dict[str, Any],
    login_hint: str | None = None,
) -> tuple[AuthFlowState, dict[str, str]]:
    """Generate state + PKCE, persist AuthFlowState, build provider query params.

    Returns (flow_state, provider_query_params). The caller decides whether
    to redirect the browser to the provider or surface the URL some other way
    (e.g. JSON response for SPA-initiated link flows).
    """
    state = secrets.token_hex(16)
    provider_verifier, provider_challenge, provider_challenge_method = (
        generate_provider_pkce(provider)
    )

    flow_state = AuthFlowState(
        kind=kind,
        provider_id=provider.id,
        state=state,
        provider_code_verifier=provider_verifier,
        completion_state=completion_state,
    )

    context.secondary_storage.set(
        f"{_STATE_KEY_PREFIX}{state}",
        flow_state.model_dump_json(),
    )

    proxy_redirect_uri = build_proxy_redirect_uri(request, context.base_url)

    query_params = provider.build_authorization_params(
        state=state,
        proxy_redirect_uri=proxy_redirect_uri,
        response_type="code",
        code_challenge=provider_challenge,
        code_challenge_method=provider_challenge_method,
        login_hint=login_hint,
    )

    return flow_state, query_params


async def parse_callback_and_load_state(
    provider: OAuth2Provider,
    request: AsyncHTTPRequest,
    context: Context,
) -> tuple[CallbackData, AuthFlowState]:
    """Extract callback data and load the persisted flow state.

    Raises OAuth2Exception if the callback reports an error, state is
    missing or unknown, or the persisted payload is malformed. Does not
    validate whether a provider `code` is present — that check happens
    after state is loaded so the caller can surface errors appropriately.
    """
    callback_data = await provider.extract_callback_data(request)

    if callback_data.error:
        logger.error("OAuth error: %s", callback_data.error)
        raise OAuth2Exception(
            error="access_denied",
            error_description=f"Authorization failed: {callback_data.error}",
        )

    state = callback_data.state
    if not state:
        logger.error("No state found in request")
        raise OAuth2Exception(
            error="server_error",
            error_description="No state found in request",
        )

    raw = context.secondary_storage.get(f"{_STATE_KEY_PREFIX}{state}")
    if raw is None:
        logger.error("No flow state found in secondary storage")
        raise OAuth2Exception(
            error="server_error",
            error_description="Provider data not found",
        )

    try:
        flow_state = AuthFlowState.model_validate_json(raw)
    except ValidationError as e:
        logger.error("Invalid flow state", exc_info=e)
        raise OAuth2Exception(
            error="server_error",
            error_description="Invalid provider data",
        ) from e

    return callback_data, flow_state


def exchange_and_resolve_user(
    provider: OAuth2Provider,
    context: Context,
    *,
    provider_code: str,
    provider_code_verifier: str | None,
    proxy_redirect_uri: str,
    callback_extra: dict[str, Any] | None,
) -> ProviderAuthResult:
    """Exchange provider code for tokens, fetch user info, resolve/create local user.

    Used by completions that want an immediate local user after the provider
    round-trip (session, auth_code). LinkCompletion does not call this —
    link flows defer provider token exchange to /finalize-link.

    Raises OAuth2Exception on any failure in the pipeline.
    """
    token_response = provider.exchange_code(
        provider_code, proxy_redirect_uri, provider_code_verifier
    )
    user_info = provider.get_user_info(token_response, context, callback_extra)
    validated = provider.validate_user_info(user_info)

    social_account = context.accounts_storage.find_social_account(
        provider=provider.id,
        provider_user_id=validated.provider_user_id,
    )

    if social_account is not None:
        context.accounts_storage.update_social_account(
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
        user = context.accounts_storage.find_user_by_id(social_account.user_id)
        if user is None:
            raise OAuth2Exception(
                error="server_error",
                error_description="User not found for social account",
            )
        return ProviderAuthResult(
            user=user,
            social_account=social_account,
            is_new_user=False,
            provider_tokens=token_response,
            user_info=user_info,
            validated=validated,
        )

    if validated.email is None:
        raise OAuth2Exception(
            error="server_error",
            error_description="No email provided by the identity provider",
        )

    user: User | None = None
    if provider.can_auto_link(context, validated.email_verified):
        user = context.accounts_storage.find_user_by_email(validated.email)

    is_new_user = False
    if user is None:
        existing_user = context.accounts_storage.find_user_by_email(validated.email)
        if existing_user is not None:
            raise OAuth2Exception(
                error="account_not_linked",
                error_description=(
                    "An account with this email exists but could not be linked automatically."
                ),
            )

        if (
            context.config.get("require_verified_email", False)
            and validated.email_verified is not True
        ):
            raise OAuth2Exception(
                error="email_not_verified",
                error_description=(
                    "Please verify your email with the provider before signing up."
                ),
            )

        try:
            user = context.accounts_storage.create_user(
                user_info=cast(dict[str, Any], user_info),
                email=validated.email,
                email_verified=validated.email_verified or False,
            )
        except CrossAuthException as e:
            raise OAuth2Exception(
                error=e.error,
                error_description=e.error_description or "",
            ) from e
        is_new_user = True

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
        is_login_method=True,
    )

    return ProviderAuthResult(
        user=user,
        social_account=social_account,
        is_new_user=is_new_user,
        provider_tokens=token_response,
        user_info=user_info,
        validated=validated,
    )


def exchange_and_attach_social_account(
    user: User,
    provider: OAuth2Provider,
    context: Context,
    *,
    provider_code: str,
    provider_code_verifier: str | None,
    proxy_redirect_uri: str,
    callback_extra: dict[str, Any] | None,
    is_login_method: bool,
) -> SocialAccount:
    """Exchange provider code and attach the resulting SocialAccount to a known user.

    Used by flows that link an additional provider account to an already-resolved
    local user (ConnectCompletion directly, LinkCompletion after /finalize-link
    verifies the SPA's PKCE challenge).

    Policy checks enforced here:
    - account_linking.enabled must be true
    - provider must trust email or provider must report email_verified=True
    - provider email must match user email (unless allow_different_emails)
    - if a SocialAccount for this provider_user_id already exists, it must
      belong to the same user (idempotent update)

    Raises OAuth2Exception on any failure.
    """
    account_linking = context.config.get("account_linking", {})
    if not account_linking.get("enabled", False):
        raise OAuth2Exception(
            error="linking_disabled",
            error_description="Account linking is not enabled.",
        )

    token_response = provider.exchange_code(
        provider_code, proxy_redirect_uri, provider_code_verifier
    )
    user_info = provider.get_user_info(token_response, context, callback_extra)
    validated = provider.validate_user_info(user_info)

    if not provider.trust_email and validated.email_verified is not True:
        raise OAuth2Exception(
            error="email_not_verified",
            error_description="Cannot link account: email not verified by provider.",
        )

    if not provider.allows_different_emails(context, validated.email, user.email):
        raise OAuth2Exception(
            error="email_mismatch",
            error_description="Provider email does not match account email.",
        )

    social_account = context.accounts_storage.find_social_account(
        provider=provider.id,
        provider_user_id=validated.provider_user_id,
    )

    if social_account is not None:
        if social_account.user_id != user.id:
            raise OAuth2Exception(
                error="already_linked",
                error_description="Social account is already linked to a different user.",
            )
        context.accounts_storage.update_social_account(
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
        return social_account

    return context.accounts_storage.create_social_account(
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
        is_login_method=is_login_method,
    )
