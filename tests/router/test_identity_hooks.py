"""Before hooks cannot change an identity Cross-Auth has already verified.

Hooks may deny an operation or adjust display data, provider tokens, and
``extra_fields``. Changing the provider identity, the signed-in user, or a
social account's owner or login eligibility raises ``ValueError`` before
anything is resolved or saved. This holds whether a hook mutates the event in
place or returns a replacement.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
import respx
from fastapi import FastAPI
from fastapi.testclient import TestClient

from cross_auth.fastapi import CrossAuth
from cross_auth.hooks import (
    BeforeOAuthCallbackEvent,
    BeforeOAuthFinalizeLinkEvent,
    BeforeOAuthLinkEvent,
    BeforeSocialAccountCreateEvent,
    BeforeSocialAccountUpdateEvent,
    BeforeTokenPasswordEvent,
)
from cross_auth.social_providers.oauth import ValidatedUserInfo
from tests.conftest import (
    TEST_PASSWORD,
    MemoryAccountsStorage,
    MemorySessionStorage,
    SocialAccount,
    User,
)

from .conftest import mock_token_and_userinfo, start_provider_auth

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
