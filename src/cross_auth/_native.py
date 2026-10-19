"""Native/SDK sign-in: verify a provider ``id_token`` and resolve its user.

Framework-neutral: it needs only a ``Context`` and the registered providers.
Callers decide separately whether to start a session.
"""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Mapping
from typing import Any

from ._auth_flow import ResolvedSocialAccount, ResolvedUser, resolve_user_for_sign_in
from ._context import Context
from .exceptions import CrossAuthException
from .hooks import AfterOAuthIdTokenEvent, BeforeOAuthIdTokenEvent
from .social_providers.oauth import OAuth2Exception, OAuth2Provider
from .social_providers.oidc import OIDCProvider


class _NoTokenResponse:
    """Native id_token sign-ins have no OAuth token exchange: there is no
    access or refresh token to store on the social account."""

    access_token = None
    refresh_token = None
    access_token_expires_at = None
    refresh_token_expires_at = None
    scope = None


_NO_TOKEN_RESPONSE = _NoTokenResponse()


def verify_nonce(claims: dict[str, Any], nonce: str) -> None:
    # Some native SDK integrations send a SHA-256 digest to the provider;
    # the provider echoes that value rather than hashing it itself.
    if not isinstance(nonce, str) or not nonce:
        raise OAuth2Exception(
            error="invalid_token",
            error_description="Expected nonce must be a non-empty string",
        )

    claim = claims.get("nonce")
    if not isinstance(claim, str) or not claim:
        raise OAuth2Exception(
            error="invalid_token",
            error_description="id_token has no nonce claim to verify",
        )
    try:
        expected = nonce.encode("utf-8")
        received = claim.encode("utf-8")
    except UnicodeError as exc:
        raise OAuth2Exception(
            error="invalid_token", error_description="Invalid nonce encoding"
        ) from exc

    hashed = hashlib.sha256(expected).hexdigest().encode("ascii")
    if not (
        secrets.compare_digest(received, expected)
        or secrets.compare_digest(received, hashed)
    ):
        raise OAuth2Exception(
            error="invalid_token",
            error_description="id_token nonce mismatch",
        )


def sign_in_with_id_token(
    *,
    context: Context,
    providers: Mapping[str, OAuth2Provider],
    provider: str,
    id_token: str,
    user_info: dict[str, Any] | None = None,
    nonce: str | None = None,
) -> tuple[ResolvedUser, ResolvedSocialAccount]:
    """Validate ``id_token`` and find or create its user.

    Runs the ``oauth.id_token`` hooks. Does not start a session.
    """
    registered = providers.get(provider)
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

    event = context.hooks.run_before(
        "oauth.id_token",
        BeforeOAuthIdTokenEvent(
            provider=provider, id_token=id_token, user_info=user_info
        ),
    )

    claims = registered.validate_id_token(event.id_token, context.secondary_storage)
    if nonce is not None:
        verify_nonce(claims, nonce)

    # Validate identity before adding unsigned metadata, including for
    # providers with custom claim mapping or validation.
    verified_user_info = registered.extract_user_info_from_claims(claims)
    validated = registered.validate_user_info(verified_user_info)
    merged: dict[str, Any] = {**verified_user_info}
    # The token's signature protects its claims, not the separate user_info
    # dictionary. A caller could send their own valid token with someone
    # else's ID or email in that dictionary. Merging every field would let
    # them change which account is selected. Allow only display fields here
    # so apps can still supply names returned separately by providers like
    # Apple, without accepting caller-supplied identity or permission fields.
    for key in ("name", "first_name", "last_name", "picture"):
        if event.user_info is not None and key in event.user_info:
            merged[key] = event.user_info[key]

    resolved_user, resolved_account = resolve_user_for_sign_in(
        provider=registered,
        context=context,
        validated=validated,
        user_info=merged,
        token_response=_NO_TOKEN_RESPONSE,
    )

    after_event = AfterOAuthIdTokenEvent(
        provider=provider,
        user=resolved_user.user,
        created=resolved_user.created,
        social_account=resolved_account.account,
    )
    context.accounts_storage.on_commit(
        lambda: context.hooks.run_after("oauth.id_token", after_event)
    )
    return resolved_user, resolved_account
