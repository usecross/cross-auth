"""A shared API connection must never choose or change the login owner."""

from urllib.parse import parse_qs, urlparse

import pytest
import respx
from fastapi import FastAPI
from fastapi.testclient import TestClient

from cross_auth._session import get_session
from tests.conftest import SocialAccount, User

from .conftest import mock_token_and_userinfo, start_provider_auth
from .test_link_flow import _LINK_CODE_VERIFIER, _store_link_code


@pytest.fixture
def personal_account(accounts_storage):
    account = SocialAccount(
        id="personal-github",
        user_id="personal",
        provider="fake",
        provider_user_id="patrick91",
        access_token="personal-token",
        is_login_method=True,
    )
    accounts_storage.data["personal"] = User(
        id="personal",
        email="personal@example.com",
        email_verified=True,
        hashed_password=None,
        social_accounts=[account],
    )
    return account


def _client(build_auth, accounts_storage, *, shared=True):
    accounts_storage.shared_connections = shared
    auth = build_auth(
        config={
            "session": {"cookies": {"auth": True}},
            "account_linking": {
                "enabled": True,
                "allow_different_emails": True,
                "allow_shared_connections": shared,
            },
        }
    )
    app = FastAPI()
    app.include_router(auth.router)
    return TestClient(app, follow_redirects=False)


def _connect(client):
    response = client.get("/fake/connect", headers={"Authorization": "Bearer test"})
    state = parse_qs(urlparse(response.headers["location"]).query)["state"][0]
    return client.get(
        "/fake/callback",
        params={"code": "provider-code", "state": state},
        headers={"Authorization": "Bearer test"},
    )


@respx.mock
def test_shared_connect_and_reconnect_only_update_work_credentials(
    build_auth, accounts_storage, personal_account
):
    mock_token_and_userinfo(provider_user_id="patrick91")

    with _client(build_auth, accounts_storage) as client:
        assert _connect(client).status_code == 302

        work_account = accounts_storage.find_social_account(
            provider="fake", provider_user_id="patrick91", user_id="test"
        )
        assert work_account is not None
        assert work_account.is_login_method is False

        work_account.access_token = "old-work-token"
        assert _connect(client).status_code == 302

    assert work_account.access_token == "provider-access-token"
    assert personal_account.access_token == "personal-token"
    assert len(accounts_storage.data["test"].social_accounts) == 1


@pytest.mark.parametrize("has_login_owner", [True, False])
@respx.mock
def test_shared_identity_sign_in_requires_and_selects_login_owner(
    build_auth, accounts_storage, personal_account, session_storage, has_login_owner
):
    personal_account.is_login_method = has_login_owner
    accounts_storage.data["test"].social_accounts.append(
        SocialAccount(
            id="work-github",
            user_id="test",
            provider="fake",
            provider_user_id="patrick91",
            access_token="work-token",
            is_login_method=False,
        )
    )
    mock_token_and_userinfo(provider_user_id="patrick91")

    with _client(build_auth, accounts_storage) as client:
        _, state = start_provider_auth(client, "/fake/login")
        response = client.get(
            "/fake/callback", params={"code": "provider-code", "state": state}
        )

    if has_login_owner:
        assert response.status_code == 302
        session = get_session(response.cookies["session_id"], session_storage)
        assert session is not None
        assert session.user_id == "personal"
        assert personal_account.access_token == "provider-access-token"
    else:
        assert response.status_code == 400
        assert response.json()["error"] == "access_denied"
        assert personal_account.access_token == "personal-token"

    assert accounts_storage.data["test"].social_accounts[0].access_token == "work-token"
    assert len(accounts_storage.data) == 2


@pytest.mark.parametrize(
    ("shared", "allow_login", "success"),
    [(True, False, True), (True, True, False), (False, False, False)],
)
@respx.mock
def test_link_sharing_preserves_exclusive_login_owner(
    build_auth,
    secondary_storage,
    accounts_storage,
    personal_account,
    shared,
    allow_login,
    success,
):
    mock_token_and_userinfo(provider_user_id="patrick91")
    code = _store_link_code(secondary_storage)

    with _client(build_auth, accounts_storage, shared=shared) as client:
        response = client.post(
            "/fake/finalize-link",
            headers={"Authorization": "Bearer test"},
            json={
                "link_code": code,
                "code_verifier": _LINK_CODE_VERIFIER,
                "allow_login": allow_login,
            },
        )

    assert response.status_code == (200 if success else 400)
    if success:
        work = accounts_storage.data["test"].social_accounts[0]
        assert work.is_login_method is False
    else:
        assert response.json()["error"] == "account_already_linked"
        assert accounts_storage.data["test"].social_accounts == []

    assert personal_account.is_login_method is True
    assert personal_account.access_token == "personal-token"


@respx.mock
def test_sign_in_does_not_promote_own_connection_created_after_initial_lookup(
    build_auth, accounts_storage, personal_account, monkeypatch
):
    personal_account.is_login_method = False
    personal_account.user_id = "test"
    accounts_storage.data["personal"].social_accounts.clear()
    has_social_account = accounts_storage.has_social_account

    def lookup_then_connect(**kwargs):
        exists = has_social_account(**kwargs)
        accounts_storage.data["test"].social_accounts.append(personal_account)
        return exists

    monkeypatch.setattr(accounts_storage, "has_social_account", lookup_then_connect)
    mock_token_and_userinfo(email="test@example.com", provider_user_id="patrick91")

    with _client(build_auth, accounts_storage) as client:
        _, state = start_provider_auth(client, "/fake/login")
        response = client.get(
            "/fake/callback", params={"code": "provider-code", "state": state}
        )

    assert response.status_code == 400
    assert response.json()["error"] == "account_already_linked"
    assert accounts_storage.data["test"].social_accounts == [personal_account]
    assert personal_account.is_login_method is False
    assert personal_account.access_token == "personal-token"


@respx.mock
def test_exclusive_policy_rejects_existing_connection_even_with_shared_storage(
    build_auth, accounts_storage, personal_account
):
    mock_token_and_userinfo(provider_user_id="patrick91")

    with _client(build_auth, accounts_storage, shared=False) as client:
        accounts_storage.shared_connections = True
        response = _connect(client)

    assert response.status_code == 400
    assert response.json()["error"] == "account_already_linked"
    assert accounts_storage.data["test"].social_accounts == []
    assert personal_account.access_token == "personal-token"
