"""sign_in_with_id_token: the headless sibling of the OAuth callback for
native/SDK logins (Apple ASAuthorization, Google Credential Manager)."""

import hashlib
from typing import Any

import pytest

from cross_auth import AccountsStorage, SecondaryStorage
from cross_auth.exceptions import CrossAuthException
from cross_auth.fastapi import CrossAuth
from cross_auth.hooks import AfterOAuthIdTokenEvent, BeforeOAuthIdTokenEvent
from cross_auth.social_providers.github import GitHubProvider
from cross_auth.social_providers.oauth import OAuth2Exception
from cross_auth.social_providers.oidc import OIDCProvider

VALID_TOKEN = "valid-id-token"  # noqa: S105


class StubOIDCProvider(OIDCProvider):
    """OIDC provider with canned claims; JWT crypto is covered by the
    provider test suites, this suite covers the sign-in flow around it."""

    id = "stub"

    def __init__(self, claims: dict[str, Any]):
        super().__init__(client_id="stub-client")
        self.claims = claims
        self.validated_tokens: list[str] = []

    def validate_id_token(
        self, id_token: str, secondary_storage: SecondaryStorage
    ) -> dict[str, Any]:
        self.validated_tokens.append(id_token)
        if id_token != VALID_TOKEN:
            raise OAuth2Exception(error="invalid_token", error_description="bad token")
        return dict(self.claims)


def _make_auth(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    provider: Any,
    **kwargs: Any,
) -> CrossAuth:
    return CrossAuth(
        providers=[provider],
        storage=secondary_storage,
        accounts_storage=accounts_storage,
        trusted_origins=[],
        **kwargs,
    )


def test_creates_user_with_normalized_email_and_no_tokens(
    secondary_storage: SecondaryStorage,
    accounts_storage,
):
    provider = StubOIDCProvider(
        {"sub": "native-1", "email": "  New.User@Example.COM  ", "email_verified": True}
    )
    auth = _make_auth(secondary_storage, accounts_storage, provider)

    user, created = auth.sign_in_with_id_token("stub", VALID_TOKEN)

    assert created is True
    assert provider.validated_tokens == [VALID_TOKEN]
    # Email normalized by the same core the web callback uses.
    assert user.email == "new.user@example.com"
    account = accounts_storage.find_social_account(
        provider="stub", provider_user_id="native-1"
    )
    assert account is not None
    # No OAuth exchange happened, so there are no tokens to store.
    assert account.access_token is None
    assert account.refresh_token is None

    # Same token again: existing social account resolves to the same user.
    again, created_again = auth.sign_in_with_id_token("stub", VALID_TOKEN)
    assert created_again is False
    assert again.id == user.id


def test_links_to_existing_account_only_when_linking_enabled(
    secondary_storage: SecondaryStorage,
    accounts_storage,
):
    # The fixture pre-seeds test@example.com; the provider reports the same
    # email (different case) for a brand-new provider subject.
    claims = {"sub": "native-2", "email": "Test@Example.com", "email_verified": True}

    strict = _make_auth(secondary_storage, accounts_storage, StubOIDCProvider(claims))
    with pytest.raises(CrossAuthException) as excinfo:
        strict.sign_in_with_id_token("stub", VALID_TOKEN)
    assert excinfo.value.error == "account_not_linked"

    linking = _make_auth(
        secondary_storage,
        accounts_storage,
        StubOIDCProvider(claims),
        config={"account_linking": {"enabled": True}},
    )
    existing = accounts_storage.find_user_by_email("test@example.com")
    user, created = linking.sign_in_with_id_token("stub", VALID_TOKEN)
    assert created is False
    assert user.id == existing.id


def test_rejects_unknown_and_non_oidc_providers(
    secondary_storage: SecondaryStorage,
    accounts_storage,
):
    github = GitHubProvider(client_id="x", client_secret="y")
    auth = _make_auth(secondary_storage, accounts_storage, github)

    with pytest.raises(CrossAuthException) as excinfo:
        auth.sign_in_with_id_token("missing", VALID_TOKEN)
    assert excinfo.value.error == "invalid_request"

    with pytest.raises(CrossAuthException) as excinfo:
        auth.sign_in_with_id_token("github", VALID_TOKEN)
    assert "id_token" in str(excinfo.value.error_description)


def test_hooks_can_rewrite_user_info_block_and_observe(
    secondary_storage: SecondaryStorage,
    accounts_storage,
):
    from dataclasses import replace

    provider = StubOIDCProvider(
        {"sub": "native-3", "email": "hooked@example.com", "email_verified": True}
    )
    auth = _make_auth(secondary_storage, accounts_storage, provider)

    created_user_info: dict[str, Any] = {}
    original_create_user = accounts_storage.create_user

    def recording_create_user(*, user_info, email, email_verified):
        created_user_info.update(user_info)
        return original_create_user(
            user_info=user_info, email=email, email_verified=email_verified
        )

    accounts_storage.create_user = recording_create_user

    seen_after: list[AfterOAuthIdTokenEvent] = []

    @auth.before("oauth.id_token")
    def add_name(event: BeforeOAuthIdTokenEvent):
        if event.user_info is None:
            return replace(event, user_info={"first_name": "Hooked"})
        return None

    @auth.after("oauth.id_token")
    def observe(event: AfterOAuthIdTokenEvent) -> None:
        seen_after.append(event)

    user, created = auth.sign_in_with_id_token("stub", VALID_TOKEN)

    assert created is True
    # The overlay from the before-hook reached the storage signup hooks.
    assert created_user_info["first_name"] == "Hooked"
    [event] = seen_after
    assert event.provider == "stub"
    assert event.created is True
    assert event.user.id == user.id

    @auth.before("oauth.id_token")
    def block(event: BeforeOAuthIdTokenEvent):
        raise CrossAuthException("access_denied")

    with pytest.raises(CrossAuthException):
        auth.sign_in_with_id_token("stub", VALID_TOKEN)


def test_nonce_matches_raw_or_hashed_claim(
    secondary_storage: SecondaryStorage,
    accounts_storage,
):
    raw = "client-generated-nonce"
    hashed_claims = {
        "sub": "native-4",
        "email": "nonce@example.com",
        "email_verified": True,
        "nonce": hashlib.sha256(raw.encode()).hexdigest(),
    }
    auth = _make_auth(
        secondary_storage, accounts_storage, StubOIDCProvider(hashed_claims)
    )

    user, _ = auth.sign_in_with_id_token("stub", VALID_TOKEN, nonce=raw)
    assert user.email == "nonce@example.com"

    with pytest.raises(OAuth2Exception):
        auth.sign_in_with_id_token("stub", VALID_TOKEN, nonce="wrong-nonce")

    no_nonce = _make_auth(
        secondary_storage,
        accounts_storage,
        StubOIDCProvider(
            {"sub": "native-5", "email": "bare@example.com", "email_verified": True}
        ),
    )
    with pytest.raises(OAuth2Exception):
        no_nonce.sign_in_with_id_token("stub", VALID_TOKEN, nonce=raw)
