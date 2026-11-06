"""Identity resolution and account writes shared by browser and native sign-in."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, NamedTuple, TypedDict

from ._context import Context
from ._login import require_immediate_commit
from ._storage import SocialAccount, SocialAccountCreate, User
from .exceptions import CrossAuthException
from .hooks import (
    AfterSocialAccountCreateEvent,
    AfterSocialAccountUpdateEvent,
    AfterUserCreateEvent,
    BeforeOAuthCallbackEvent,
    BeforeOAuthFinalizeLinkEvent,
    BeforeSocialAccountCreateEvent,
    BeforeSocialAccountUpdateEvent,
    BeforeUserCreateEvent,
    ProviderSnapshot,
    SocialAccountSnapshot,
)
from .models.oauth_token_response import TokenResponse
from .social_providers.oauth import OAuth2Provider, ValidatedUserInfo


def _same_id(left: object, right: object) -> bool:
    return str(left) == str(right)


class _CredentialFields(TypedDict):
    access_token: str | None
    refresh_token: str | None
    access_token_expires_at: datetime | None
    refresh_token_expires_at: datetime | None
    scope: str | None


@dataclass(frozen=True)
class ProviderCredentials:
    access_token: str | None = None
    refresh_token: str | None = None
    access_token_expires_at: datetime | None = None
    refresh_token_expires_at: datetime | None = None
    scope: str | None = None

    @classmethod
    def of(cls, source: TokenResponse | SocialAccount | None) -> ProviderCredentials:
        if source is None:
            return cls()

        return cls(
            access_token=source.access_token,
            refresh_token=source.refresh_token,
            access_token_expires_at=source.access_token_expires_at,
            refresh_token_expires_at=source.refresh_token_expires_at,
            scope=source.scope,
        )

    def fields(self) -> _CredentialFields:
        return {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "access_token_expires_at": self.access_token_expires_at,
            "refresh_token_expires_at": self.refresh_token_expires_at,
            "scope": self.scope,
        }


@dataclass(frozen=True)
class _AccountIdentity:
    user_id: Any
    provider: str
    provider_user_id: str
    provider_email: str | None
    provider_email_verified: bool | None
    is_login_method: bool

    @classmethod
    def of(
        cls, event: BeforeSocialAccountCreateEvent | BeforeSocialAccountUpdateEvent
    ) -> _AccountIdentity:
        return cls(
            user_id=event.user_id,
            provider=event.provider,
            provider_user_id=event.provider_user_id,
            provider_email=event.provider_email,
            provider_email_verified=event.provider_email_verified,
            is_login_method=event.is_login_method,
        )


class ResolvedUser(NamedTuple):
    user: User
    created: bool


class ResolvedSocialAccount(NamedTuple):
    account: SocialAccount
    created: bool


def require_committed_accounts(context: Context) -> None:
    """Refuse to issue a credential or code for uncommitted account changes.

    Raises while an accounts storage defers its commit callbacks, as one that
    joined an application transaction does. Built-in sign-in does not support
    that: the login could outlive a rolled-back user.
    """
    require_immediate_commit(
        context.accounts_storage.on_commit,
        "Sign-in cannot issue a login while account changes are uncommitted; "
        "do not run the sign-in flow inside an application transaction",
    )


def _create_user_with_identity(
    *,
    context: Context,
    user_info: dict[str, Any],
    email: str,
    email_verified: bool,
    identity: Callable[[User], SocialAccountCreate],
) -> tuple[User, SocialAccount]:
    raw_claims = _raw_identity_claims(user_info)
    event = context.hooks.run_before(
        "user.create",
        BeforeUserCreateEvent(
            user_info=user_info,
            email=email,
            email_verified=email_verified,
            extra_fields={},
        ),
    )
    if (
        event.email != email
        or event.email_verified != email_verified
        or _raw_identity_claims(event.user_info) != raw_claims
    ):
        raise ValueError(
            "user.create before hooks cannot change email, email_verified or "
            f"{_RAW_IDENTITY_CLAIMS_TEXT}; configure normalize_email to "
            "canonicalize emails"
        )

    identity_data: SocialAccountCreate | None = None

    def prepare_identity(user: User) -> SocialAccountCreate:
        nonlocal identity_data
        identity_data = identity(user)
        return identity_data

    user, social_account = context.accounts_storage.create_user_with_identity(
        user={
            "user_info": event.user_info,
            "email": email,
            "email_verified": email_verified,
            "extra_fields": event.extra_fields,
        },
        identity=prepare_identity,
    )
    assert identity_data is not None

    user_event = AfterUserCreateEvent(user_info=event.user_info, user=user)
    account_event = AfterSocialAccountCreateEvent(
        user_info=identity_data["user_info"], social_account=social_account
    )

    def run_after_hooks() -> None:
        context.hooks.run_after("user.create", user_event)
        context.hooks.run_after("social_account.create", account_event)

    context.accounts_storage.on_commit(run_after_hooks)
    return user, social_account


def _prepare_social_account(
    *,
    context: Context,
    user_id: Any,
    provider: str,
    provider_user_id: str,
    access_token: str | None,
    refresh_token: str | None,
    access_token_expires_at: datetime | None,
    refresh_token_expires_at: datetime | None,
    scope: str | None,
    user_info: dict[str, Any],
    provider_email: str | None,
    provider_email_verified: bool | None,
    is_login_method: bool,
) -> SocialAccountCreate:
    raw_claims = _raw_identity_claims(user_info)
    event = BeforeSocialAccountCreateEvent(
        user_id=user_id,
        provider=provider,
        provider_user_id=provider_user_id,
        access_token=access_token,
        refresh_token=refresh_token,
        access_token_expires_at=access_token_expires_at,
        refresh_token_expires_at=refresh_token_expires_at,
        scope=scope,
        user_info=user_info,
        provider_email=provider_email,
        provider_email_verified=provider_email_verified,
        is_login_method=is_login_method,
        extra_fields={},
    )
    identity = _AccountIdentity.of(event)
    event = context.hooks.run_before("social_account.create", event)
    if (
        _AccountIdentity.of(event) != identity
        or _raw_identity_claims(event.user_info) != raw_claims
    ):
        raise ValueError(
            "social_account.create before hooks cannot change user_id, provider, "
            "provider_user_id, is_login_method, provider_email, "
            f"provider_email_verified or {_RAW_IDENTITY_CLAIMS_TEXT}"
        )

    return SocialAccountCreate(
        user_id=user_id,
        provider=provider,
        provider_user_id=provider_user_id,
        access_token=event.access_token,
        refresh_token=event.refresh_token,
        access_token_expires_at=event.access_token_expires_at,
        refresh_token_expires_at=event.refresh_token_expires_at,
        scope=event.scope,
        user_info=event.user_info,
        provider_email=provider_email,
        provider_email_verified=provider_email_verified,
        is_login_method=is_login_method,
        extra_fields=event.extra_fields,
    )


def _check_social_account_ownership(
    context: Context,
    *,
    user_id: Any,
    provider: str,
    provider_user_id: str,
    is_login_method: bool,
) -> None:
    # Database constraints enforce this policy when requests race these checks.
    allow_shared_connections = context.config.get("account_linking", {}).get(
        "allow_shared_connections", False
    )

    if not allow_shared_connections:
        identity_exists = context.accounts_storage.has_social_account(
            provider=provider, provider_user_id=provider_user_id
        )
        if (
            identity_exists
            and context.accounts_storage.find_social_account(
                provider=provider,
                provider_user_id=provider_user_id,
                user_id=user_id,
            )
            is None
        ):
            raise CrossAuthException("account_already_linked")
    elif is_login_method:
        login_account = context.accounts_storage.find_social_account(
            provider=provider,
            provider_user_id=provider_user_id,
            is_login_method=True,
        )

        if login_account is not None and not _same_id(login_account.user_id, user_id):
            raise CrossAuthException("account_already_linked")


def _create_social_account(
    *,
    context: Context,
    user_id: Any,
    provider: str,
    provider_user_id: str,
    access_token: str | None,
    refresh_token: str | None,
    access_token_expires_at: datetime | None,
    refresh_token_expires_at: datetime | None,
    scope: str | None,
    user_info: dict[str, Any],
    provider_email: str | None,
    provider_email_verified: bool | None,
    is_login_method: bool,
) -> SocialAccount:
    data = _prepare_social_account(
        context=context,
        user_id=user_id,
        provider=provider,
        provider_user_id=provider_user_id,
        access_token=access_token,
        refresh_token=refresh_token,
        access_token_expires_at=access_token_expires_at,
        refresh_token_expires_at=refresh_token_expires_at,
        scope=scope,
        user_info=user_info,
        provider_email=provider_email,
        provider_email_verified=provider_email_verified,
        is_login_method=is_login_method,
    )
    _check_social_account_ownership(
        context,
        user_id=data["user_id"],
        provider=data["provider"],
        provider_user_id=data["provider_user_id"],
        is_login_method=data["is_login_method"],
    )

    social_account = context.accounts_storage.create_social_account(**data)
    after_event = AfterSocialAccountCreateEvent(
        user_info=data["user_info"], social_account=social_account
    )
    context.accounts_storage.on_commit(
        lambda: context.hooks.run_after("social_account.create", after_event)
    )

    return social_account


def _update_social_account(
    *,
    context: Context,
    social_account: SocialAccount,
    access_token: str | None,
    refresh_token: str | None,
    access_token_expires_at: datetime | None,
    refresh_token_expires_at: datetime | None,
    scope: str | None,
    user_info: dict[str, Any],
    provider_email: str | None,
    provider_email_verified: bool | None,
    enable_login: bool = False,
) -> SocialAccount:
    snapshot = SocialAccountSnapshot.of(social_account)
    raw_claims = _raw_identity_claims(user_info)
    event = BeforeSocialAccountUpdateEvent(
        social_account=snapshot,
        user_id=snapshot.user_id,
        provider=snapshot.provider,
        provider_user_id=snapshot.provider_user_id,
        access_token=access_token,
        refresh_token=refresh_token,
        access_token_expires_at=access_token_expires_at,
        refresh_token_expires_at=refresh_token_expires_at,
        scope=scope,
        user_info=user_info,
        provider_email=provider_email,
        provider_email_verified=provider_email_verified,
        is_login_method=snapshot.is_login_method,
        extra_fields={},
    )
    identity = _AccountIdentity.of(event)
    event = context.hooks.run_before("social_account.update", event)
    if (
        event.social_account != snapshot
        or _AccountIdentity.of(event) != identity
        or _raw_identity_claims(event.user_info) != raw_claims
    ):
        raise ValueError(
            "social_account.update before hooks cannot change the account, its "
            "user_id, provider, provider_user_id, is_login_method, "
            f"provider_email, provider_email_verified or {_RAW_IDENTITY_CLAIMS_TEXT}"
        )

    if enable_login and not social_account.is_login_method:
        _check_social_account_ownership(
            context,
            user_id=social_account.user_id,
            provider=social_account.provider,
            provider_user_id=social_account.provider_user_id,
            is_login_method=True,
        )

    updated_social_account = context.accounts_storage.update_social_account(
        social_account.id,
        access_token=event.access_token,
        refresh_token=event.refresh_token,
        access_token_expires_at=event.access_token_expires_at,
        refresh_token_expires_at=event.refresh_token_expires_at,
        scope=event.scope,
        user_info=event.user_info,
        provider_email=provider_email,
        provider_email_verified=provider_email_verified,
        enable_login=enable_login,
        extra_fields=event.extra_fields,
    )
    after_event = AfterSocialAccountUpdateEvent(
        user_info=event.user_info,
        social_account=updated_social_account,
    )
    context.accounts_storage.on_commit(
        lambda: context.hooks.run_after("social_account.update", after_event)
    )

    return updated_social_account


# The standard identity claims of ``UserInfo``. The rest of ``user_info`` is
# profile metadata hooks may adjust, but storage adapters may read these keys.
_RAW_IDENTITY_CLAIMS = ("id", "email", "email_verified")
_RAW_IDENTITY_CLAIMS_TEXT = "the user_info id, email or email_verified"


def _raw_identity_claims(user_info: Mapping[str, object]) -> dict[str, object]:
    return {key: user_info[key] for key in _RAW_IDENTITY_CLAIMS if key in user_info}


@dataclass(frozen=True)
class VerifiedIdentityGuard:
    provider: ProviderSnapshot
    validated: ValidatedUserInfo
    raw_claims: dict[str, object]

    @classmethod
    def of(
        cls,
        provider: OAuth2Provider,
        validated: ValidatedUserInfo,
        user_info: Mapping[str, object],
    ) -> VerifiedIdentityGuard:
        return cls(
            ProviderSnapshot.of(provider), validated, _raw_identity_claims(user_info)
        )

    def check(
        self,
        event_name: str,
        event: BeforeOAuthCallbackEvent | BeforeOAuthFinalizeLinkEvent,
    ) -> None:
        # Hooks may edit profile metadata, not claims that select or authorize
        # the account. Capture these before dispatch, including mutable raw data.
        if (
            event.provider != self.provider
            or event.validated_user_info != self.validated
            or _raw_identity_claims(event.user_info) != self.raw_claims
        ):
            raise ValueError(
                f"{event_name} before hooks cannot change the provider, the verified "
                f"provider_user_id, email or email_verified, or {_RAW_IDENTITY_CLAIMS_TEXT}"
            )


def resolve_user_for_sign_in(
    *,
    provider: OAuth2Provider,
    context: Context,
    validated: ValidatedUserInfo,
    user_info: dict[str, Any],
    token_response: TokenResponse | None,
) -> tuple[ResolvedUser, ResolvedSocialAccount]:
    """Check whether a provider identity may sign in, then resolve its user."""
    social_account = context.accounts_storage.find_social_account(
        provider=provider.id,
        provider_user_id=validated.provider_user_id,
        is_login_method=True,
    )

    # Connections grant API access without implicitly granting sign-in access.
    if social_account is None and context.accounts_storage.has_social_account(
        provider=provider.id, provider_user_id=validated.provider_user_id
    ):
        raise CrossAuthException(
            "access_denied", error_description="Sign-in is not allowed"
        )

    return resolve_or_create_user(
        social_account=social_account,
        provider=provider,
        context=context,
        validated=validated,
        user_info=user_info,
        token_response=token_response,
    )


def resolve_or_create_user(
    *,
    provider: OAuth2Provider,
    context: Context,
    validated: ValidatedUserInfo,
    user_info: dict[str, Any],
    token_response: TokenResponse | None,
    social_account: SocialAccount | None,
) -> tuple[ResolvedUser, ResolvedSocialAccount]:
    """Find/create a user and social account after login eligibility is checked."""
    if social_account:
        # Native verification refreshes identity without replacing web credentials.
        credentials = ProviderCredentials.of(
            token_response if token_response is not None else social_account
        )
        social_account = _update_social_account(
            context=context,
            social_account=social_account,
            **credentials.fields(),
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

    # Lookups and creation use the normalized (canonical) form; the raw
    # provider email is still stored on the social account as provider_email.
    email = context.normalize_email(validated.email)
    user = context.accounts_storage.find_user_by_email(email)
    can_auto_link = provider.can_auto_link(context, validated.email_verified)

    if user is not None and not can_auto_link:
        raise CrossAuthException(
            "account_not_linked",
            error_description=(
                "An account with this email exists but could not be linked "
                "automatically."
            ),
        )

    if user is None:
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

        def prepare_identity(created_user: User) -> SocialAccountCreate:
            return _prepare_social_account(
                context=context,
                user_id=created_user.id,
                provider=provider.id,
                provider_user_id=validated.provider_user_id,
                **ProviderCredentials.of(token_response).fields(),
                user_info=user_info,
                provider_email=validated.email,
                provider_email_verified=validated.email_verified,
                is_login_method=True,
            )

        user, account = _create_user_with_identity(
            context=context,
            user_info=user_info,
            email=email,
            email_verified=validated.email_verified or False,
            identity=prepare_identity,
        )

        return (
            ResolvedUser(user=user, created=True),
            ResolvedSocialAccount(account=account, created=True),
        )

    created_social_account = _create_social_account(
        context=context,
        user_id=user.id,
        provider=provider.id,
        provider_user_id=validated.provider_user_id,
        **ProviderCredentials.of(token_response).fields(),
        user_info=user_info,
        provider_email=validated.email,
        provider_email_verified=validated.email_verified,
        is_login_method=True,
    )

    return (
        ResolvedUser(user=user, created=False),
        ResolvedSocialAccount(account=created_social_account, created=True),
    )


def attach_social_account(
    *,
    provider: OAuth2Provider,
    context: Context,
    user: User,
    validated: ValidatedUserInfo,
    user_info: dict[str, Any],
    token_response: TokenResponse,
    allow_login: bool,
) -> ResolvedSocialAccount:
    """Attach/refresh an identity after the flow's email policy is checked."""
    social_account = context.accounts_storage.find_social_account(
        provider=provider.id,
        provider_user_id=validated.provider_user_id,
        user_id=user.id,
    )
    credentials = ProviderCredentials.of(token_response)

    if social_account is not None:
        account = _update_social_account(
            context=context,
            social_account=social_account,
            enable_login=allow_login,
            **credentials.fields(),
            user_info=user_info,
            provider_email=validated.email,
            provider_email_verified=validated.email_verified,
        )

        return ResolvedSocialAccount(account=account, created=False)

    account = _create_social_account(
        context=context,
        user_id=user.id,
        provider=provider.id,
        provider_user_id=validated.provider_user_id,
        **credentials.fields(),
        user_info=user_info,
        provider_email=validated.email,
        provider_email_verified=validated.email_verified,
        is_login_method=allow_login,
    )

    return ResolvedSocialAccount(account=account, created=True)


def _check_login_link_email(
    provider: OAuth2Provider,
    context: Context,
    validated: ValidatedUserInfo,
    user: User,
) -> None:
    """Require a verified provider email, matching the user's unless allowed."""
    if not provider.trusts_email(validated.email_verified):
        raise CrossAuthException(
            "email_not_verified",
            "Cannot link account: email not verified by provider.",
        )

    if not provider.allows_different_emails(context, validated.email, user.email):
        raise CrossAuthException(
            "email_mismatch",
            "Provider email does not match account email.",
        )
