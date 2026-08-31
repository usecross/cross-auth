from unittest.mock import Mock

import pytest
import respx
from fastapi import FastAPI
from fastapi.testclient import TestClient

from cross_auth._storage import AccountsStorage, SecondaryStorage, SessionStorage

from .conftest import (
    FakeProvider,
    _build_auth,
    mock_token_and_userinfo,
    start_provider_auth,
)


def _recording_client(
    *,
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
    provider: FakeProvider,
    account_linking_enabled: bool,
) -> tuple[TestClient, Mock]:
    recording_storage = Mock(wraps=accounts_storage, spec=accounts_storage)
    auth = _build_auth(
        storage=secondary_storage,
        accounts_storage=recording_storage,
        session_storage=session_storage,
        providers=[provider],
        config={
            "session": {"cookies": {"auth": True}},
            "account_linking": {"enabled": account_linking_enabled},
        },
    )
    app = FastAPI()
    app.include_router(auth.router)
    return TestClient(app, follow_redirects=False), recording_storage


@respx.mock
def test_missing_user_has_one_normalized_email_lookup_when_auto_linking_allowed(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
    fake_provider: FakeProvider,
):
    client, recording_storage = _recording_client(
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
    recording_storage.find_user_by_email.assert_called_once_with("new.user@example.com")
    assert accounts_storage.find_user_by_email("new.user@example.com") is not None


@pytest.mark.parametrize("account_linking_enabled", [False, True])
@respx.mock
def test_existing_user_has_one_email_lookup_and_respects_auto_link_policy(
    account_linking_enabled: bool,
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
    fake_provider: FakeProvider,
):
    client, recording_storage = _recording_client(
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

    recording_storage.find_user_by_email.assert_called_once_with("test@example.com")
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
