"""Login promotion requires an authenticated, verified link flow."""

from dataclasses import replace

import pytest
import respx
from fastapi import FastAPI
from fastapi.testclient import TestClient

from cross_auth._session import get_session
from tests.conftest import SocialAccount

from .conftest import mock_token_and_userinfo, start_provider_auth
from .test_link_flow import _LINK_CODE_VERIFIER, _store_link_code
from .test_shared_connections import _client, personal_account  # noqa: F401


@pytest.fixture
def connection(accounts_storage):
    account = SocialAccount(
        id="work-account",
        user_id="test",
        provider="fake",
        provider_user_id="patrick91",
        access_token="old-token",
        is_login_method=False,
    )
    accounts_storage.data["test"].social_accounts.append(account)
    return account


def finalize(client, code, *, allow_login):
    return client.post(
        "/fake/finalize-link",
        headers={"Authorization": "Bearer test"},
        json={
            "link_code": code,
            "code_verifier": _LINK_CODE_VERIFIER,
            "allow_login": allow_login,
        },
    )


@pytest.mark.parametrize("already_login", [True, False])
@pytest.mark.parametrize("allow_login", [True, False])
@respx.mock
def test_link_can_enable_but_never_disable_login(
    build_auth,
    accounts_storage,
    secondary_storage,
    connection,
    already_login,
    allow_login,
):
    connection.is_login_method = already_login
    code = _store_link_code(secondary_storage)
    mock_token_and_userinfo(email="test@example.com", provider_user_id="patrick91")

    with _client(build_auth, accounts_storage, shared=False) as client:
        response = finalize(client, code, allow_login=allow_login)

    assert response.status_code == 200
    assert connection.is_login_method is (already_login or allow_login)
    assert connection.access_token == "provider-access-token"
    assert accounts_storage.data["test"].social_accounts == [connection]


@respx.mock
def test_promoted_connection_can_sign_in(
    build_auth, accounts_storage, secondary_storage, session_storage, connection
):
    code = _store_link_code(secondary_storage)
    mock_token_and_userinfo(email="test@example.com", provider_user_id="patrick91")

    with _client(build_auth, accounts_storage, shared=False) as client:
        assert finalize(client, code, allow_login=True).status_code == 200

        _, state = start_provider_auth(client, "/fake/login")
        response = client.get(
            "/fake/callback", params={"code": "new-provider-code", "state": state}
        )

    assert response.status_code == 302
    session = get_session(response.cookies["session_id"], session_storage)
    assert session is not None
    assert session.user_id == connection.user_id


@pytest.mark.parametrize("other_login_owner", [True, False])
@respx.mock
def test_promotion_preserves_single_login_owner(
    build_auth,
    accounts_storage,
    secondary_storage,
    personal_account,  # noqa: F811 - imported pytest fixture
    connection,
    other_login_owner,
):
    personal_account.is_login_method = other_login_owner
    code = _store_link_code(secondary_storage)
    mock_token_and_userinfo(provider_user_id="patrick91")

    with _client(build_auth, accounts_storage) as client:
        response = finalize(client, code, allow_login=True)

    if other_login_owner:
        assert response.status_code == 400
        assert response.json()["error"] == "account_already_linked"
        assert connection.access_token == "old-token"
    else:
        assert response.status_code == 200
        assert connection.access_token == "provider-access-token"

    assert connection.is_login_method is not other_login_owner
    assert personal_account.is_login_method is other_login_owner
    assert personal_account.access_token == "personal-token"


@respx.mock
def test_unverified_identity_cannot_promote_connection(
    build_auth, accounts_storage, secondary_storage, connection, fake_provider
):
    fake_provider.trust_email = False
    code = _store_link_code(secondary_storage)
    mock_token_and_userinfo(provider_user_id="patrick91", email_verified=False)

    with _client(build_auth, accounts_storage, shared=False) as client:
        response = finalize(client, code, allow_login=True)

    assert response.status_code == 400
    assert response.json()["error"] == "email_not_verified"
    assert connection.is_login_method is False
    assert connection.access_token == "old-token"


@respx.mock
def test_finalize_hook_can_prevent_promotion(build_auth, secondary_storage, connection):
    auth = build_auth(config={"account_linking": {"enabled": True}})

    @auth.before("oauth.finalize_link")
    def keep_connection_only(event):
        return replace(event, allow_login=False)

    app = FastAPI()
    app.include_router(auth.router)
    code = _store_link_code(secondary_storage)
    mock_token_and_userinfo(email="test@example.com", provider_user_id="patrick91")

    with TestClient(app) as client:
        response = finalize(client, code, allow_login=True)

    assert response.status_code == 200
    assert connection.is_login_method is False
    assert connection.access_token == "provider-access-token"
