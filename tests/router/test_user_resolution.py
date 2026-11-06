from urllib.parse import parse_qs, urlparse

import pytest
import respx
from fastapi import FastAPI
from fastapi.testclient import TestClient

from cross_auth._storage import AccountsStorage, SecondaryStorage, SessionStorage
from cross_auth.hooks import AfterOAuthCallbackEvent

from .conftest import (
    FakeProvider,
    _build_auth,
    mock_token_and_userinfo,
    start_provider_auth,
)


@pytest.mark.parametrize("flow", ["session", "token"])
@respx.mock
def test_connected_account_cannot_sign_in(
    flow,
    client,
    auth,
    accounts_storage,
    session_storage,
    secondary_storage,
):
    accounts_storage.create_social_account(
        user_id="test",
        provider="fake",
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
    seen_after: list[AfterOAuthCallbackEvent] = []

    @auth.after("oauth.callback")
    def observe(event: AfterOAuthCallbackEvent) -> None:
        seen_after.append(event)

    mock_token_and_userinfo(email="test@example.com", provider_user_id="connected-1")
    params = (
        {
            "client_id": "app-client",
            "redirect_uri": "http://client.example/cb",
            "state": "client-state",
            "response_type": "code",
            "code_challenge": "client-challenge",
            "code_challenge_method": "S256",
        }
        if flow == "token"
        else None
    )
    path = "/fake/authorize" if flow == "token" else "/fake/login"
    _, state = start_provider_auth(client, path, params=params)
    response = client.get(
        "/fake/callback", params={"code": "provider-code", "state": state}
    )

    if flow == "token":
        assert response.status_code == 302
        query = parse_qs(urlparse(response.headers["location"]).query)
        assert query == {
            "error": ["access_denied"],
            "error_description": ["Sign-in is not allowed"],
            "state": ["client-state"],
        }
    else:
        assert response.status_code == 400
        assert response.json() == {
            "error": "access_denied",
            "error_description": "Sign-in is not allowed",
        }
    account = accounts_storage.find_social_account(
        provider="fake", provider_user_id="connected-1", user_id="test"
    )
    assert account is not None
    assert account.access_token == "stored-access"
    assert account.refresh_token == "stored-refresh"
    assert account.is_login_method is False
    assert not seen_after
    assert not session_storage.records
    assert "session_id" not in response.cookies
    assert not any(key.startswith("oauth:code:") for key in secondary_storage.data)


def _sign_in_client(
    *,
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
    provider: FakeProvider,
    account_linking_enabled: bool,
) -> TestClient:
    auth = _build_auth(
        storage=secondary_storage,
        accounts_storage=accounts_storage,
        session_storage=session_storage,
        providers=[provider],
        config={
            "session": {"cookies": {"auth": True}},
            "account_linking": {"enabled": account_linking_enabled},
        },
    )
    app = FastAPI()
    app.include_router(auth.router)
    return TestClient(app, follow_redirects=False)


@respx.mock
def test_missing_user_signs_up_with_normalized_email(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
    fake_provider: FakeProvider,
):
    client = _sign_in_client(
        secondary_storage=secondary_storage,
        accounts_storage=accounts_storage,
        session_storage=session_storage,
        provider=fake_provider,
        account_linking_enabled=True,
    )

    with client:
        mock_token_and_userinfo(
            email="  New.User@Example.COM  ", provider_user_id="new-provider-user"
        )
        _, state = start_provider_auth(client, "/fake/login")
        response = client.get(
            "/fake/callback", params={"code": "provider-code", "state": state}
        )

    assert response.status_code == 302
    user = accounts_storage.find_user_by_email("new.user@example.com")
    assert user is not None
    account = accounts_storage.find_social_account(
        provider="fake", provider_user_id="new-provider-user", user_id=user.id
    )
    assert account is not None
    assert account.is_login_method is True
    assert len(list(accounts_storage.list_social_accounts(user_id=user.id))) == 1


@pytest.mark.parametrize("account_linking_enabled", [False, True])
@respx.mock
def test_existing_user_respects_auto_link_policy_after_email_normalization(
    account_linking_enabled: bool,
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
    fake_provider: FakeProvider,
):
    client = _sign_in_client(
        secondary_storage=secondary_storage,
        accounts_storage=accounts_storage,
        session_storage=session_storage,
        provider=fake_provider,
        account_linking_enabled=account_linking_enabled,
    )

    with client:
        mock_token_and_userinfo(
            email="Test@Example.COM", provider_user_id="existing-provider-user"
        )
        _, state = start_provider_auth(client, "/fake/login")
        response = client.get(
            "/fake/callback", params={"code": "provider-code", "state": state}
        )

    social_account = accounts_storage.find_social_account(
        provider="fake", provider_user_id="existing-provider-user"
    )

    if account_linking_enabled:
        assert response.status_code == 302
        assert social_account is not None
        assert social_account.user_id == "test"
    else:
        assert response.status_code == 400
        assert response.json()["error"] == "account_not_linked"
        assert social_account is None
