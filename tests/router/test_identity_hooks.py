"""Before hooks cannot change an identity Cross-Auth has already verified.

Hooks may deny an operation or adjust display data, provider tokens, and
``extra_fields``. Changing the provider identity, the verified email claims,
the signed-in user, or a social account's owner or login eligibility raises
``ValueError`` before anything is resolved or saved. This holds whether a hook
mutates the event in place or returns a replacement.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Callable, TypedDict
from urllib.parse import parse_qs, urlparse

import pytest
import respx
from fastapi import FastAPI
from fastapi.testclient import TestClient

from cross_auth.fastapi import CrossAuth
from cross_auth.exceptions import CrossAuthException
from cross_auth.hooks import (
    AfterOAuthCallbackEvent,
    BeforeOAuthCallbackEvent,
    BeforeOAuthFinalizeLinkEvent,
    BeforeOAuthLinkEvent,
    BeforeSocialAccountCreateEvent,
    BeforeSocialAccountUpdateEvent,
    BeforeTokenPasswordEvent,
    BeforeUserCreateEvent,
)
from cross_auth.social_providers.oauth import UserInfo, ValidatedUserInfo
from tests.conftest import (
    TEST_PASSWORD,
    MemoryAccountsStorage,
    MemorySessionStorage,
    SocialAccount,
    User,
)

from .conftest import FakeProvider, mock_token_and_userinfo, start_provider_auth

# S256 challenge for the code verifier "test".
_CODE_CHALLENGE = "n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg"
_CODE_VERIFIER = "test"


def _client(auth: CrossAuth) -> TestClient:
    app = FastAPI()
    app.include_router(auth.router)
    return TestClient(app, follow_redirects=False)


def _all_social_accounts(accounts_storage: MemoryAccountsStorage) -> list[Any]:
    return [
        account
        for user in accounts_storage.data.values()
        for account in user.social_accounts
    ]


def _add_other_user(accounts_storage: MemoryAccountsStorage) -> User:
    other = User(
        id="other",
        email="other@example.com",
        email_verified=True,
        hashed_password=None,
        social_accounts=[],
    )
    accounts_storage.data["other"] = other
    return other


def _rewrite_provider_user_id_in_place(
    event: BeforeOAuthCallbackEvent | BeforeOAuthFinalizeLinkEvent,
) -> None:
    event.validated_user_info.provider_user_id = "victim-id"


def _rewrite_provider_user_id_by_replacement(
    event: BeforeOAuthCallbackEvent | BeforeOAuthFinalizeLinkEvent,
) -> BeforeOAuthCallbackEvent | BeforeOAuthFinalizeLinkEvent:
    validated = event.validated_user_info
    return replace(
        event,
        user_info={**event.user_info, "id": "victim-id"},
        validated_user_info=ValidatedUserInfo(
            email=validated.email,
            provider_user_id="victim-id",
            email_verified=validated.email_verified,
        ),
    )


_PROVIDER_IDENTITY_REWRITES = pytest.mark.parametrize(
    "rewrite",
    [_rewrite_provider_user_id_in_place, _rewrite_provider_user_id_by_replacement],
    ids=["in_place", "replacement"],
)


# --- oauth.callback -------------------------------------------------------


@_PROVIDER_IDENTITY_REWRITES
@respx.mock
def test_callback_cannot_sign_in_as_another_provider_identity(
    auth: CrossAuth,
    accounts_storage: MemoryAccountsStorage,
    session_storage: MemorySessionStorage,
    rewrite,
):
    accounts_storage.data["test"].social_accounts.append(
        SocialAccount(
            id="victim-account",
            user_id="test",
            provider="fake",
            provider_user_id="victim-id",
        )
    )
    logins: list[object] = []
    auth.before("oauth.callback")(rewrite)
    auth.before("login")(logins.append)
    auth.before("social_account.update")(logins.append)

    mock_token_and_userinfo(email="attacker@example.com", provider_user_id="attacker")
    with _client(auth) as client:
        _, state = start_provider_auth(client, "/fake/login")
        with pytest.raises(ValueError, match="cannot change the provider"):
            client.get("/fake/callback", params={"code": "code", "state": state})

    assert logins == []
    assert session_storage.records == {}
    assert list(accounts_storage.data) == ["test"]
    assert [a.id for a in _all_social_accounts(accounts_storage)] == ["victim-account"]


@respx.mock
def test_callback_hooks_can_still_adjust_claim_data(
    auth: CrossAuth,
    accounts_storage: MemoryAccountsStorage,
    session_storage: MemorySessionStorage,
):
    @auth.before("oauth.callback")
    def add_display_name(event: BeforeOAuthCallbackEvent) -> BeforeOAuthCallbackEvent:
        return replace(event, user_info={**event.user_info, "name": "Alice"})

    seen: list[dict[str, Any]] = []
    auth.before("user.create")(lambda event: seen.append(event.user_info))

    mock_token_and_userinfo(email="alice@example.com", provider_user_id="alice-id")
    with _client(auth) as client:
        _, state = start_provider_auth(client, "/fake/login")
        resp = client.get("/fake/callback", params={"code": "code", "state": state})

    assert resp.status_code == 302
    assert seen[0]["name"] == "Alice"
    [account] = accounts_storage.data["alice-id"].social_accounts
    assert account.provider_user_id == "alice-id"
    assert len(session_storage.records) == 1


@respx.mock
def test_raw_user_info_email_is_metadata_not_a_verified_claim(
    build_auth, accounts_storage: MemoryAccountsStorage
):
    auth = build_auth(
        config={
            "session": {"cookies": {"auth": True}},
            "account_linking": {"enabled": True},
        }
    )

    @auth.before("oauth.callback")
    def rewrite_raw_email(event: BeforeOAuthCallbackEvent) -> BeforeOAuthCallbackEvent:
        return replace(
            event,
            user_info={
                **event.user_info,
                "email": "test@example.com",
                "email_verified": True,
            },
        )

    mock_token_and_userinfo(email="alice@example.com", provider_user_id="alice-id")
    with _client(auth) as client:
        _, state = start_provider_auth(client, "/fake/login")
        resp = client.get("/fake/callback", params={"code": "code", "state": state})

    assert resp.status_code == 302
    assert accounts_storage.data["test"].social_accounts == []
    user = accounts_storage.data["alice-id"]
    assert user.email == "alice@example.com"
    [account] = user.social_accounts
    assert account.provider_email == "alice@example.com"


# --- oauth.link and oauth.finalize_link -------------------------------------


def _linking_auth(build_auth) -> CrossAuth:
    return build_auth(config={"account_linking": {"enabled": True}})


def _start_link(client: TestClient) -> str:
    resp = client.post(
        "/fake/link",
        headers={"Authorization": "Bearer test"},
        json={
            "redirect_uri": "http://client.example/cb",
            "code_challenge": _CODE_CHALLENGE,
            "code_challenge_method": "S256",
            "client_id": "app-client",
        },
    )
    assert resp.status_code == 200, resp.text
    return parse_qs(urlparse(resp.json()["authorization_url"]).query)["state"][0]


def _link_code(client: TestClient) -> str:
    state = _start_link(client)
    callback = client.get(
        "/fake/callback", params={"code": "provider-code", "state": state}
    )
    return parse_qs(urlparse(callback.headers["location"]).query)["link_code"][0]


def _finalize_link(client: TestClient, link_code: str):
    return client.post(
        "/fake/finalize-link",
        headers={"Authorization": "Bearer test"},
        json={"link_code": link_code, "code_verifier": _CODE_VERIFIER},
    )


def test_link_cannot_change_the_signed_in_user(
    build_auth, accounts_storage: MemoryAccountsStorage, secondary_storage
):
    auth = _linking_auth(build_auth)
    test_user = accounts_storage.data["test"]

    @auth.before("oauth.link")
    def change_user(event: BeforeOAuthLinkEvent) -> None:
        assert event.user is test_user
        test_user.id = "other"

    with _client(auth) as client:
        with pytest.raises(ValueError, match="oauth.link before hooks cannot"):
            client.post(
                "/fake/link",
                headers={"Authorization": "Bearer test"},
                json={
                    "redirect_uri": "http://client.example/cb",
                    "code_challenge": _CODE_CHALLENGE,
                    "code_challenge_method": "S256",
                    "client_id": "app-client",
                },
            )

    assert not any(key.startswith("oauth:") for key in secondary_storage.data)


@_PROVIDER_IDENTITY_REWRITES
@respx.mock
def test_finalize_link_cannot_attach_another_provider_identity(
    build_auth, accounts_storage: MemoryAccountsStorage, rewrite
):
    auth = _linking_auth(build_auth)
    auth.before("oauth.finalize_link")(rewrite)
    creates: list[object] = []
    auth.before("social_account.create")(creates.append)

    mock_token_and_userinfo(email="test@example.com", provider_user_id="linked-id")
    with _client(auth) as client:
        link_code = _link_code(client)
        with pytest.raises(ValueError, match="cannot change the provider"):
            _finalize_link(client, link_code)

    assert creates == []
    assert _all_social_accounts(accounts_storage) == []


def _replace_user(
    event: BeforeOAuthFinalizeLinkEvent, test_user: User, other: User
) -> BeforeOAuthFinalizeLinkEvent | None:
    return replace(event, user=other)


def _change_user_in_place(
    event: BeforeOAuthFinalizeLinkEvent, test_user: User, other: User
) -> BeforeOAuthFinalizeLinkEvent | None:
    assert event.user is test_user
    test_user.id = other.id
    return None


@pytest.mark.parametrize(
    "rewrite", [_change_user_in_place, _replace_user], ids=["in_place", "replacement"]
)
@respx.mock
def test_finalize_link_cannot_attach_to_another_user(
    build_auth, accounts_storage: MemoryAccountsStorage, rewrite
):
    test_user = accounts_storage.data["test"]
    other = _add_other_user(accounts_storage)
    auth = _linking_auth(build_auth)
    auth.before("oauth.finalize_link")(lambda event: rewrite(event, test_user, other))

    mock_token_and_userinfo(email="test@example.com", provider_user_id="linked-id")
    with _client(auth) as client:
        link_code = _link_code(client)
        with pytest.raises(ValueError, match="cannot change the user"):
            _finalize_link(client, link_code)

    assert _all_social_accounts(accounts_storage) == []


@respx.mock
def test_finalize_link_hooks_can_still_adjust_policy_and_claim_data(
    build_auth, accounts_storage: MemoryAccountsStorage
):
    auth = _linking_auth(build_auth)

    @auth.before("oauth.finalize_link")
    def add_display_name(
        event: BeforeOAuthFinalizeLinkEvent,
    ) -> BeforeOAuthFinalizeLinkEvent:
        return replace(
            event,
            allow_login=False,
            user_info={**event.user_info, "name": "Linked"},
        )

    seen: list[dict[str, Any]] = []
    auth.before("social_account.create")(lambda event: seen.append(event.user_info))

    mock_token_and_userinfo(email="test@example.com", provider_user_id="linked-id")
    with _client(auth) as client:
        resp = _finalize_link(client, _link_code(client))

    assert resp.status_code == 200
    assert seen[0]["name"] == "Linked"
    [account] = accounts_storage.data["test"].social_accounts
    assert account.provider_user_id == "linked-id"
    assert account.is_login_method is False


# --- social_account.create and social_account.update ----------------------


def _connect(client: TestClient):
    resp = client.get(
        "/fake/connect",
        params={"next": "/profile"},
        headers={"Authorization": "Bearer test"},
    )
    state = parse_qs(urlparse(resp.headers["location"]).query)["state"][0]
    return client.get(
        "/fake/callback",
        params={"code": "provider-code", "state": state},
        headers={"Authorization": "Bearer test"},
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"user_id": "other"},
        {"provider": "other-provider"},
        {"provider_user_id": "victim-id"},
        {"is_login_method": True},
    ],
    ids=["user_id", "provider", "provider_user_id", "is_login_method"],
)
@respx.mock
def test_social_account_create_cannot_change_owner_or_identity(
    auth: CrossAuth, accounts_storage: MemoryAccountsStorage, changes
):
    _add_other_user(accounts_storage)
    auth.before("social_account.create")(lambda event: replace(event, **changes))

    mock_token_and_userinfo(email="test@example.com", provider_user_id="connect-id")
    with _client(auth) as client:
        with pytest.raises(ValueError, match="social_account.create before hooks"):
            _connect(client)

    assert _all_social_accounts(accounts_storage) == []


@respx.mock
def test_social_account_create_hooks_can_still_adjust_tokens_and_extra_fields(
    auth: CrossAuth, accounts_storage: MemoryAccountsStorage
):
    @auth.before("social_account.create")
    def encrypt_token(
        event: BeforeSocialAccountCreateEvent,
    ) -> BeforeSocialAccountCreateEvent:
        return replace(
            event,
            access_token=f"encrypted:{event.access_token}",
            extra_fields={"provider_username": "demo"},
        )

    mock_token_and_userinfo(email="test@example.com", provider_user_id="connect-id")
    with _client(auth) as client:
        assert _connect(client).status_code == 302

    [account] = accounts_storage.data["test"].social_accounts
    assert account.access_token == "encrypted:provider-access-token"
    assert account.is_login_method is False
    assert accounts_storage.last_social_account_extra_fields == {
        "provider_username": "demo"
    }


def _update_user_id(event: BeforeSocialAccountUpdateEvent, account: SocialAccount):
    return replace(event, user_id="other")


def _update_login_method(event: BeforeSocialAccountUpdateEvent, account: SocialAccount):
    return replace(event, is_login_method=True)


def _update_account_owner_in_place(
    event: BeforeSocialAccountUpdateEvent, account: SocialAccount
):
    assert event.social_account is account
    account.user_id = "other"


def _update_account_id_in_place(
    event: BeforeSocialAccountUpdateEvent, account: SocialAccount
):
    assert event.social_account is account
    account.id = "other-account"


@pytest.mark.parametrize(
    "rewrite",
    [
        _update_user_id,
        _update_login_method,
        _update_account_owner_in_place,
        _update_account_id_in_place,
    ],
    ids=["user_id", "is_login_method", "owner_in_place", "account_in_place"],
)
@respx.mock
def test_social_account_update_cannot_change_target_owner_or_identity(
    auth: CrossAuth,
    accounts_storage: MemoryAccountsStorage,
    monkeypatch: pytest.MonkeyPatch,
    rewrite,
):
    _add_other_user(accounts_storage)
    mock_token_and_userinfo(email="test@example.com", provider_user_id="connect-id")
    with _client(auth) as client:
        assert _connect(client).status_code == 302

        updates: list[object] = []
        monkeypatch.setattr(
            accounts_storage,
            "update_social_account",
            lambda *args, **kwargs: updates.append(args),
        )
        [account] = accounts_storage.data["test"].social_accounts
        auth.before("social_account.update")(lambda event: rewrite(event, account))
        with pytest.raises(ValueError, match="social_account.update before hooks"):
            _connect(client)

    assert updates == []


@respx.mock
def test_social_account_update_hooks_can_still_adjust_tokens(
    auth: CrossAuth, accounts_storage: MemoryAccountsStorage
):
    mock_token_and_userinfo(email="test@example.com", provider_user_id="connect-id")
    with _client(auth) as client:
        assert _connect(client).status_code == 302

        @auth.before("social_account.update")
        def rotate_token(
            event: BeforeSocialAccountUpdateEvent,
        ) -> BeforeSocialAccountUpdateEvent:
            return replace(event, access_token="rotated")

        assert _connect(client).status_code == 302

    [account] = accounts_storage.data["test"].social_accounts
    assert account.access_token == "rotated"


# --- token.password -------------------------------------------------------


def test_password_grant_cannot_change_the_user(
    auth: CrossAuth,
    accounts_storage: MemoryAccountsStorage,
    session_storage: MemorySessionStorage,
):
    test_user = accounts_storage.data["test"]
    other = _add_other_user(accounts_storage)
    logins: list[object] = []
    auth.before("login")(logins.append)

    @auth.before("token.password")
    def change_user(event: BeforeTokenPasswordEvent) -> None:
        assert event.user is test_user
        test_user.id = other.id

    with _client(auth) as client:
        with pytest.raises(ValueError, match="token.password before hooks cannot"):
            client.post(
                "/token",
                data={
                    "grant_type": "password",
                    "client_id": "app-client",
                    "username": "test@example.com",
                    "password": TEST_PASSWORD,
                },
            )

    assert logins == []
    assert session_storage.records == {}


# --- verified email claims ------------------------------------------------
#
# Hooks may read the provider's email claims to deny an operation, but cannot
# change them: they decide auto-linking, ``require_verified_email``, link
# validation, and the email stored on users and social accounts. Canonical
# forms come from the configured ``normalize_email`` callback.


class _OptionalEmailProvider(FakeProvider):
    """A custom provider whose identities may arrive without an email."""

    def validate_user_info(self, user_info: UserInfo) -> ValidatedUserInfo:
        return ValidatedUserInfo(
            email=user_info["email"],
            provider_user_id=str(user_info["id"]),
            email_verified=user_info["email_verified"],
        )


class _ClaimChanges(TypedDict, total=False):
    email: str | None
    email_verified: bool | None


ClaimHook = Callable[[BeforeOAuthCallbackEvent | BeforeOAuthFinalizeLinkEvent], Any]


def _change_claims_in_place(changes: _ClaimChanges) -> ClaimHook:
    def hook(event: BeforeOAuthCallbackEvent | BeforeOAuthFinalizeLinkEvent) -> None:
        validated = event.validated_user_info
        if "email" in changes:
            validated.email = changes["email"]
        if "email_verified" in changes:
            validated.email_verified = changes["email_verified"]

    return hook


def _change_claims_by_replacement(changes: _ClaimChanges) -> ClaimHook:
    def hook(
        event: BeforeOAuthCallbackEvent | BeforeOAuthFinalizeLinkEvent,
    ) -> BeforeOAuthCallbackEvent | BeforeOAuthFinalizeLinkEvent:
        validated = replace(event.validated_user_info, **changes)
        user_info = {**event.user_info, **changes}
        return replace(event, user_info=user_info, validated_user_info=validated)

    return hook


_CLAIM_REWRITE_MODES = pytest.mark.parametrize(
    "rewrite",
    [_change_claims_in_place, _change_claims_by_replacement],
    ids=["in_place", "replacement"],
)


def _email_policy_auth(build_auth) -> CrossAuth:
    # The provider does not vouch for emails, so ``email_verified`` alone
    # decides auto-linking, signup, and linking.
    provider = _OptionalEmailProvider(
        client_id="fake-client-id", client_secret="fake-secret", trust_email=False
    )
    return build_auth(
        providers=[provider],
        config={
            "session": {"cookies": {"auth": True}},
            "account_linking": {"enabled": True},
            "require_verified_email": True,
        },
    )


@_CLAIM_REWRITE_MODES
@pytest.mark.parametrize(
    ("email", "email_verified", "changes"),
    [
        pytest.param(
            "attacker@example.com",
            True,
            {"email": "test@example.com"},
            id="email_into_existing_user",
        ),
        pytest.param(
            "test@example.com",
            False,
            {"email_verified": True},
            id="verify_into_existing_user",
        ),
        pytest.param(
            "new@example.com",
            False,
            {"email_verified": True},
            id="verify_past_require_verified_email",
        ),
        pytest.param(
            "new@example.com", None, {"email_verified": True}, id="verify_absent"
        ),
        pytest.param("new@example.com", True, {"email_verified": False}, id="unverify"),
        pytest.param(
            None,
            None,
            {"email": "test@example.com", "email_verified": True},
            id="add_absent_email",
        ),
        pytest.param("new@example.com", True, {"email": None}, id="remove_email"),
    ],
)
@respx.mock
def test_callback_cannot_change_verified_email_claims(
    build_auth,
    accounts_storage: MemoryAccountsStorage,
    session_storage: MemorySessionStorage,
    rewrite,
    email: str | None,
    email_verified: bool | None,
    changes: _ClaimChanges,
):
    auth = _email_policy_auth(build_auth)
    auth.before("oauth.callback")(rewrite(changes))
    effects: list[object] = []
    auth.before("user.create")(effects.append)
    auth.before("social_account.create")(effects.append)
    auth.before("social_account.update")(effects.append)
    auth.before("login")(effects.append)
    auth.after("oauth.callback")(effects.append)

    mock_token_and_userinfo(
        email=email, email_verified=email_verified, provider_user_id="attacker-id"
    )
    with _client(auth) as client:
        _, state = start_provider_auth(client, "/fake/login")
        with pytest.raises(ValueError, match="email or email_verified"):
            client.get("/fake/callback", params={"code": "code", "state": state})

    assert effects == []
    assert session_storage.records == {}
    assert list(accounts_storage.data) == ["test"]
    assert _all_social_accounts(accounts_storage) == []


@_CLAIM_REWRITE_MODES
@pytest.mark.parametrize(
    ("email", "email_verified", "changes"),
    [
        pytest.param(
            "test@example.com",
            False,
            {"email_verified": True},
            id="verify_past_link_check",
        ),
        pytest.param(
            "test@example.com", None, {"email_verified": True}, id="verify_absent"
        ),
        pytest.param(
            "other@example.com",
            True,
            {"email": "test@example.com"},
            id="email_past_mismatch_check",
        ),
        pytest.param(
            None,
            None,
            {"email": "test@example.com", "email_verified": True},
            id="add_absent_email",
        ),
        pytest.param(
            "test@example.com", True, {"email_verified": False}, id="unverify"
        ),
        pytest.param("test@example.com", True, {"email": None}, id="remove_email"),
    ],
)
@respx.mock
def test_finalize_link_cannot_change_verified_email_claims(
    build_auth,
    accounts_storage: MemoryAccountsStorage,
    rewrite,
    email: str | None,
    email_verified: bool | None,
    changes: _ClaimChanges,
):
    auth = _email_policy_auth(build_auth)
    auth.before("oauth.finalize_link")(rewrite(changes))
    effects: list[object] = []
    auth.before("social_account.create")(effects.append)
    auth.before("social_account.update")(effects.append)
    auth.after("oauth.finalize_link")(effects.append)

    mock_token_and_userinfo(
        email=email, email_verified=email_verified, provider_user_id="linked-id"
    )
    with _client(auth) as client:
        link_code = _link_code(client)
        with pytest.raises(ValueError, match="email or email_verified"):
            _finalize_link(client, link_code)

    assert effects == []
    assert _all_social_accounts(accounts_storage) == []


class _UserClaimChanges(TypedDict, total=False):
    email: str
    email_verified: bool


@pytest.mark.parametrize(
    ("email_verified", "changes"),
    [
        pytest.param(True, {"email": "someone-else@example.com"}, id="email"),
        # The baseline is the canonical form from ``normalize_email``.
        pytest.param(True, {"email": "New@Example.com"}, id="denormalize_email"),
        pytest.param(False, {"email_verified": True}, id="verify"),
        pytest.param(True, {"email_verified": False}, id="unverify"),
    ],
)
@respx.mock
def test_user_create_cannot_change_email_claims(
    build_auth,
    accounts_storage: MemoryAccountsStorage,
    session_storage: MemorySessionStorage,
    email_verified: bool,
    changes: _UserClaimChanges,
):
    auth = build_auth(normalize_email=str.lower)
    auth.before("user.create")(lambda event: replace(event, **changes))
    effects: list[object] = []
    auth.before("social_account.create")(effects.append)
    auth.after("user.create")(effects.append)
    auth.before("login")(effects.append)

    mock_token_and_userinfo(
        email="New@Example.com", email_verified=email_verified, provider_user_id="new"
    )
    with _client(auth) as client:
        _, state = start_provider_auth(client, "/fake/login")
        with pytest.raises(ValueError, match="user.create before hooks cannot"):
            client.get("/fake/callback", params={"code": "code", "state": state})

    assert effects == []
    assert session_storage.records == {}
    assert list(accounts_storage.data) == ["test"]


class _ProviderClaimChanges(TypedDict, total=False):
    provider_email: str | None
    provider_email_verified: bool | None


_PROVIDER_CLAIM_REWRITES = pytest.mark.parametrize(
    ("email_verified", "changes"),
    [
        pytest.param(True, {"provider_email": "victim@example.com"}, id="email"),
        pytest.param(True, {"provider_email": None}, id="remove_email"),
        pytest.param(False, {"provider_email_verified": True}, id="verify"),
        pytest.param(None, {"provider_email_verified": True}, id="verify_absent"),
        pytest.param(True, {"provider_email_verified": False}, id="unverify"),
    ],
)


@_PROVIDER_CLAIM_REWRITES
@respx.mock
def test_social_account_create_cannot_change_provider_email_claims(
    auth: CrossAuth,
    accounts_storage: MemoryAccountsStorage,
    email_verified: bool | None,
    changes: _ProviderClaimChanges,
):
    auth.before("social_account.create")(lambda event: replace(event, **changes))

    mock_token_and_userinfo(
        email="test@example.com",
        email_verified=email_verified,
        provider_user_id="connect-id",
    )
    with _client(auth) as client:
        with pytest.raises(ValueError, match="social_account.create before hooks"):
            _connect(client)

    assert _all_social_accounts(accounts_storage) == []


@respx.mock
def test_signup_rolls_back_when_social_account_create_changes_provider_email(
    auth: CrossAuth,
    accounts_storage: MemoryAccountsStorage,
    session_storage: MemorySessionStorage,
):
    auth.before("social_account.create")(
        lambda event: replace(event, provider_email="victim@example.com")
    )

    mock_token_and_userinfo(email="new@example.com", provider_user_id="new")
    with _client(auth) as client:
        _, state = start_provider_auth(client, "/fake/login")
        with pytest.raises(ValueError, match="social_account.create before hooks"):
            client.get("/fake/callback", params={"code": "code", "state": state})

    assert list(accounts_storage.data) == ["test"]
    assert session_storage.records == {}


@_PROVIDER_CLAIM_REWRITES
@respx.mock
def test_social_account_update_cannot_change_provider_email_claims(
    auth: CrossAuth,
    accounts_storage: MemoryAccountsStorage,
    monkeypatch: pytest.MonkeyPatch,
    email_verified: bool | None,
    changes: _ProviderClaimChanges,
):
    mock_token_and_userinfo(
        email="test@example.com",
        email_verified=email_verified,
        provider_user_id="connect-id",
    )
    with _client(auth) as client:
        assert _connect(client).status_code == 302

        updates: list[object] = []
        monkeypatch.setattr(
            accounts_storage,
            "update_social_account",
            lambda *args, **kwargs: updates.append(args),
        )
        auth.before("social_account.update")(lambda event: replace(event, **changes))
        with pytest.raises(ValueError, match="social_account.update before hooks"):
            _connect(client)

    assert updates == []


@respx.mock
def test_provider_verified_email_change_refreshes_social_account(
    auth: CrossAuth, accounts_storage: MemoryAccountsStorage
):
    seen: list[tuple[str | None, bool | None]] = []

    @auth.before("social_account.update")
    def record_claims(event: BeforeSocialAccountUpdateEvent) -> None:
        seen.append((event.provider_email, event.provider_email_verified))

    mock_token_and_userinfo(
        email="old@example.com", email_verified=False, provider_user_id="connect-id"
    )
    with _client(auth) as client:
        assert _connect(client).status_code == 302
        mock_token_and_userinfo(
            email="renamed@example.com",
            email_verified=True,
            provider_user_id="connect-id",
        )
        assert _connect(client).status_code == 302

    assert seen == [("renamed@example.com", True)]
    [account] = accounts_storage.data["test"].social_accounts
    assert account.provider_email == "renamed@example.com"
    assert account.provider_email_verified is True


# --- application email policies -------------------------------------------
#
# Representative of hooks that read email claims for policy and add
# ``extra_fields``, as FastAPI Cloud does. Exercised with library fixtures only.


@respx.mock
def test_read_only_email_policies_and_extra_fields_keep_working(
    build_auth,
    accounts_storage: MemoryAccountsStorage,
    session_storage: MemorySessionStorage,
):
    auth = build_auth(normalize_email=lambda email: email.strip().lower())
    callbacks: list[tuple[str | None, bool | None, str]] = []

    @auth.before("oauth.callback")
    def reject_suspended_account(event: BeforeOAuthCallbackEvent) -> None:
        validated = event.validated_user_info
        callbacks.append(
            (validated.email, validated.email_verified, validated.provider_user_id)
        )
        if validated.email == "suspended@example.com":
            raise CrossAuthException("access_denied", "Account suspended", 403)

    @auth.before("user.create")
    def reject_disallowed_signup(event: BeforeUserCreateEvent) -> None:
        if not event.email.endswith("@example.com"):
            raise CrossAuthException("signup_not_allowed", "Signup not allowed", 403)

    @auth.before("user.create")
    def populate_full_name(event: BeforeUserCreateEvent) -> BeforeUserCreateEvent:
        full_name = event.user_info.get("name") or event.email.split("@")[0]
        return replace(
            event, extra_fields={**event.extra_fields, "full_name": full_name}
        )

    @auth.before("social_account.create")
    @auth.before("social_account.update")
    def populate_provider_username(
        event: BeforeSocialAccountCreateEvent | BeforeSocialAccountUpdateEvent,
    ) -> BeforeSocialAccountCreateEvent | BeforeSocialAccountUpdateEvent:
        username = event.user_info.get("login") or event.provider_user_id
        return replace(
            event,
            extra_fields={**event.extra_fields, "provider_username": username},
        )

    completed: list[AfterOAuthCallbackEvent] = []
    auth.after("oauth.callback")(completed.append)

    def sign_in(email: str, provider_user_id: str):
        mock_token_and_userinfo(email=email, provider_user_id=provider_user_id)
        _, state = start_provider_auth(client, "/fake/login")
        return client.get("/fake/callback", params={"code": "code", "state": state})

    with _client(auth) as client:
        assert sign_in(" Alice@Example.com", "alice-id").status_code == 302
        assert accounts_storage.last_user_extra_fields == {"full_name": "alice"}
        assert sign_in(" Alice@Example.com", "alice-id").status_code == 302

        suspended = sign_in("suspended@example.com", "suspended-id")
        assert suspended.status_code == 403
        assert suspended.json()["error"] == "access_denied"

        denied = sign_in("bob@other.org", "bob-id")
        assert denied.json()["error"] == "signup_not_allowed"

    user = accounts_storage.data["alice-id"]
    assert user.email == "alice@example.com"
    [account] = user.social_accounts
    assert account.provider_email == " Alice@Example.com"
    assert account.provider_email_verified is True
    assert accounts_storage.social_account_extra_fields_history == [
        {"provider_username": "alice-id"},
        {"provider_username": "alice-id"},
    ]
    assert callbacks == [
        (" Alice@Example.com", True, "alice-id"),
        (" Alice@Example.com", True, "alice-id"),
        ("suspended@example.com", True, "suspended-id"),
        ("bob@other.org", True, "bob-id"),
    ]
    assert [event.created_user is not None for event in completed] == [True, False]
    assert list(accounts_storage.data) == ["test", "alice-id"]
    assert len(session_storage.records) == 2
