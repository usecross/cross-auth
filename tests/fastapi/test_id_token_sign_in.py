"""sign_in_with_id_token: the headless sibling of the OAuth callback for
native/SDK logins (Apple ASAuthorization, Google Credential Manager)."""

import hashlib
from dataclasses import replace
from typing import Any
from unittest.mock import Mock

import pytest
from sqlmodel import Session

from cross_auth import AccountsStorage, SecondaryStorage
from cross_auth.exceptions import CrossAuthException
from cross_auth.fastapi import CrossAuth
from cross_auth.hooks import AfterOAuthIdTokenEvent, BeforeOAuthIdTokenEvent
from cross_auth.social_providers.github import GitHubProvider
from cross_auth.social_providers.oauth import OAuth2Exception
from cross_auth.social_providers.oidc import OIDCProvider

from ..storage.conftest import make_sqlite_engine
from ..storage.models import LeanAccountsStore

VALID_TOKEN = "valid-id-token"  # noqa: S105


def test_connected_account_cannot_sign_in(
    secondary_storage, accounts_storage, monkeypatch
):
    provider = StubOIDCProvider(
        {"sub": "connected-1", "email": "test@example.com", "email_verified": True}
    )
    auth = _make_auth(secondary_storage, accounts_storage, provider)
    accounts_storage.create_social_account(
        user_id="test",
        provider="stub",
        provider_user_id="connected-1",
        access_token="stored-access",
        refresh_token="stored-refresh",
        access_token_expires_at=None,
        refresh_token_expires_at=None,
        scope="email",
        user_info={},
        provider_email="test@example.com",
        provider_email_verified=True,
        is_login_method=False,
    )
    update = Mock(wraps=accounts_storage.update_social_account)
    monkeypatch.setattr(accounts_storage, "update_social_account", update)
    seen_after: list[AfterOAuthIdTokenEvent] = []

    @auth.after("oauth.id_token")
    def observe(event: AfterOAuthIdTokenEvent) -> None:
        seen_after.append(event)

    with pytest.raises(CrossAuthException, match="^access_denied$"):
        auth.sign_in_with_id_token("stub", VALID_TOKEN)

    update.assert_not_called()
    assert not seen_after


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
    assert user.hashed_password is None
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


def test_repeat_sign_in_works_with_tokenless_sqlmodel_storage(
    secondary_storage: SecondaryStorage,
):
    provider = StubOIDCProvider(
        {"sub": "tokenless-1", "email": "tokenless@example.com", "email_verified": True}
    )
    engine = make_sqlite_engine()
    accounts_storage = LeanAccountsStore(session_factory=lambda: Session(engine))
    auth = _make_auth(secondary_storage, accounts_storage, provider)

    committed_users = []

    @auth.after("user.create")
    def check_committed_identity(event):
        persisted_user = accounts_storage.find_user_by_id(event.user.id)
        account = accounts_storage.find_social_account(
            provider="stub", provider_user_id="tokenless-1", user_id=event.user.id
        )
        assert persisted_user is not None
        assert account is not None
        committed_users.append(persisted_user.id)

    user, created = auth.sign_in_with_id_token("stub", VALID_TOKEN)
    again, created_again = auth.sign_in_with_id_token("stub", VALID_TOKEN)

    assert created is True
    assert committed_users == [user.id]
    assert created_again is False
    assert again.id == user.id
    account = accounts_storage.find_social_account(
        provider="stub", provider_user_id="tokenless-1"
    )
    assert account is not None
    assert account.access_token is None
    assert account.refresh_token is None
    assert account.scope is None


@pytest.mark.parametrize("via_hook", [False, True])
def test_unsigned_metadata_cannot_select_another_identity(
    secondary_storage: SecondaryStorage,
    accounts_storage,
    via_hook: bool,
):
    """A native login endpoint can forward both an SDK's signed ID token and
    unsigned profile data, such as Apple's first-sign-in name. A malicious
    client can keep its own valid token but put a victim's identity in that
    profile data. Cover direct forwarding and forwarding through a before hook.
    """
    provider = StubOIDCProvider(
        {"sub": "victim", "email": "victim@example.com", "email_verified": True}
    )
    auth = _make_auth(
        secondary_storage,
        accounts_storage,
        provider,
        config={"account_linking": {"enabled": True}},
    )
    victim, _ = auth.sign_in_with_id_token("stub", VALID_TOKEN)
    provider.claims = {
        "sub": "attacker",
        "email": "attacker@example.com",
        "email_verified": False,
    }
    metadata = {
        "id": "victim",
        "sub": "victim",
        "email": "victim@example.com",
        "email_verified": True,
        "iss": "untrusted-issuer",
        "is_superuser": True,
        "name": "Display Name",
        "first_name": "Display",
        "last_name": "Name",
        "picture": "https://example.com/avatar.png",
    }
    seen_user_info: list[dict[str, Any]] = []

    @auth.before("user.create")
    def observe_user_info(event):
        seen_user_info.append(dict(event.user_info))

    if via_hook:

        @auth.before("oauth.id_token")
        def supply_metadata(event: BeforeOAuthIdTokenEvent):
            return replace(event, user_info=metadata)

    user, created = auth.sign_in_with_id_token(
        "stub", VALID_TOKEN, user_info=None if via_hook else metadata
    )

    assert created is True
    assert user.id != victim.id
    assert user.email == "attacker@example.com"
    assert user.email_verified is False
    assert seen_user_info == [
        {
            "id": "attacker",
            "email": "attacker@example.com",
            "email_verified": False,
            "name": "Display Name",
            "first_name": "Display",
            "last_name": "Name",
            "picture": "https://example.com/avatar.png",
        }
    ]
    victim_account = accounts_storage.find_social_account(
        provider="stub", provider_user_id="victim"
    )
    assert victim_account is not None
    assert victim_account.user_id == victim.id
    assert victim_account.provider_email == "victim@example.com"


@pytest.mark.parametrize("verified", [False, None])
def test_metadata_cannot_satisfy_verified_email_policy(
    secondary_storage: SecondaryStorage,
    accounts_storage,
    verified: bool | None,
):
    auth = _make_auth(
        secondary_storage,
        accounts_storage,
        StubOIDCProvider(
            {
                "sub": "unverified",
                "email": "new@example.com",
                "email_verified": verified,
            }
        ),
        config={"require_verified_email": True},
    )

    with pytest.raises(CrossAuthException, match="^email_not_verified$"):
        auth.sign_in_with_id_token(
            "stub", VALID_TOKEN, user_info={"email_verified": True}
        )

    assert accounts_storage.find_user_by_email("new@example.com") is None


def test_metadata_cannot_supply_missing_provider_email(
    secondary_storage: SecondaryStorage,
    accounts_storage,
):
    auth = _make_auth(
        secondary_storage,
        accounts_storage,
        StubOIDCProvider({"sub": "missing-email"}),
    )

    with pytest.raises(OAuth2Exception, match="^No email found in user info$"):
        auth.sign_in_with_id_token(
            "stub",
            VALID_TOKEN,
            user_info={"email": "test@example.com", "email_verified": True},
        )


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
    provider = StubOIDCProvider(
        {"sub": "native-3", "email": "hooked@example.com", "email_verified": True}
    )
    auth = _make_auth(secondary_storage, accounts_storage, provider)

    created_user_info: dict[str, Any] = {}
    original_create_user = accounts_storage.create_user

    def recording_create_user(*, user_info, email, email_verified, extra_fields=None):
        created_user_info.update(user_info)
        return original_create_user(
            user_info=user_info,
            email=email,
            email_verified=email_verified,
            extra_fields=extra_fields,
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
    # The overlay from the before hook reached account storage.
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


def test_token_less_sign_in_preserves_credentials_from_a_web_flow(
    secondary_storage: SecondaryStorage,
    accounts_storage,
):
    """Web flow stores Google-style tokens; a later native sign-in for the
    same account must refresh identity fields without clobbering them —
    background API calls depend on the stored refresh token."""
    provider = StubOIDCProvider(
        {"sub": "mixed-1", "email": "renamed@example.com", "email_verified": True}
    )
    auth = _make_auth(secondary_storage, accounts_storage, provider)

    # Simulate the earlier web callback: user + social account with tokens.
    web_user = accounts_storage.create_user(
        user_info={"id": "mixed-1"}, email="mixed@example.com", email_verified=True
    )
    accounts_storage.create_social_account(
        user_id=web_user.id,
        provider="stub",
        provider_user_id="mixed-1",
        access_token="web-access",
        refresh_token="web-refresh",
        access_token_expires_at=None,
        refresh_token_expires_at=None,
        scope="calendar.readonly",
        user_info={"id": "mixed-1"},
        provider_email="mixed@example.com",
        provider_email_verified=True,
        is_login_method=True,
    )

    user, created = auth.sign_in_with_id_token("stub", VALID_TOKEN)

    assert created is False
    assert user.id == web_user.id
    account = accounts_storage.find_social_account(
        provider="stub", provider_user_id="mixed-1"
    )
    # Credentials survived the token-less sign-in...
    assert account.access_token == "web-access"
    assert account.refresh_token == "web-refresh"
    assert account.scope == "calendar.readonly"
    # ...while identity fields refreshed from the new token's claims.
    assert account.provider_email == "renamed@example.com"


@pytest.mark.parametrize(
    ("nonce", "claim", "message"),
    [
        ("", "", "Expected nonce must be a non-empty string"),
        ("expected", "", "has no nonce claim"),
        ("expected", 42, "has no nonce claim"),
        ("expected", "é", "nonce mismatch"),
        ("expected", "\ud800", "Invalid nonce encoding"),
    ],
)
def test_invalid_native_nonce_is_rejected_before_account_creation(
    secondary_storage, accounts_storage, nonce, claim, message
):
    provider = StubOIDCProvider(
        {
            "sub": "nonce-user",
            "email": "nonce@example.com",
            "email_verified": True,
            "nonce": claim,
        }
    )
    auth = _make_auth(secondary_storage, accounts_storage, provider)

    with pytest.raises(OAuth2Exception, match=message):
        auth.sign_in_with_id_token("stub", VALID_TOKEN, nonce=nonce)

    assert accounts_storage.find_user_by_email("nonce@example.com") is None


@pytest.mark.parametrize("hashed", [False, True])
def test_native_nonce_accepts_raw_and_sdk_hashed_unicode_values(
    secondary_storage, accounts_storage, hashed
):
    nonce = "random-nonce-é"
    claim = hashlib.sha256(nonce.encode()).hexdigest() if hashed else nonce
    provider = StubOIDCProvider(
        {
            "sub": "nonce-user",
            "email": "nonce@example.com",
            "email_verified": True,
            "nonce": claim,
        }
    )
    auth = _make_auth(secondary_storage, accounts_storage, provider)

    user, created = auth.sign_in_with_id_token("stub", VALID_TOKEN, nonce=nonce)

    assert created is True
    assert user.email == "nonce@example.com"
