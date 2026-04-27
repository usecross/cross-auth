from __future__ import annotations

from typing import cast

from fastapi import FastAPI
from fastapi.testclient import TestClient

from cross_auth.exceptions import CrossAuthException
from cross_auth.fastapi import CrossAuth
from cross_auth.hooks import AfterOAuthDisconnectEvent, BeforeOAuthDisconnectEvent

from tests.conftest import SocialAccount, User as DemoUser


def _add_social_account(
    accounts_storage,
    *,
    user_id: str = "test",
    account_id: str = "fake-account",
    provider: str = "fake",
    provider_user_id: str = "fake-user",
    is_login_method: bool = True,
) -> SocialAccount:
    user = accounts_storage.find_user_by_id(user_id)
    assert user is not None
    account = SocialAccount(
        id=account_id,
        user_id=user_id,
        provider=provider,
        provider_user_id=provider_user_id,
        is_login_method=is_login_method,
    )
    user.social_accounts.append(account)
    return account


def test_disconnect_requires_authentication(client: TestClient):
    resp = client.delete("/fake/social-accounts")

    assert resp.status_code == 401
    assert resp.json() == {
        "error": "unauthorized",
        "error_description": "Must be logged in to disconnect a social account",
    }


def test_disconnect_account_route_documents_path_parameter(auth: CrossAuth):
    app = FastAPI()
    app.include_router(auth.router)

    operation = app.openapi()["paths"]["/fake/social-accounts/{social_account_id}"][
        "delete"
    ]

    assert operation["parameters"] == [
        {
            "name": "social_account_id",
            "in": "path",
            "required": True,
            "schema": {"type": "string", "title": "Social Account Id"},
        }
    ]


def test_disconnect_requires_connected_account(client: TestClient):
    resp = client.delete(
        "/fake/social-accounts", headers={"Authorization": "Bearer test"}
    )

    assert resp.status_code == 400
    assert resp.json() == {
        "error": "account_not_connected",
        "error_description": "fake account is not connected",
    }


def test_disconnect_deletes_provider_account(client: TestClient, accounts_storage):
    _add_social_account(accounts_storage)

    resp = client.delete(
        "/fake/social-accounts", headers={"Authorization": "Bearer test"}
    )

    assert resp.status_code == 200
    assert resp.json() == {"message": "fake account disconnected"}
    assert accounts_storage.find_social_account_by_id("fake-account") is None


def test_disconnect_by_provider_requires_specific_account_when_provider_has_multiple_accounts(
    client: TestClient,
    accounts_storage,
):
    _add_social_account(
        accounts_storage,
        account_id="fake-account-1",
        provider_user_id="fake-user-1",
    )
    _add_social_account(
        accounts_storage,
        account_id="fake-account-2",
        provider_user_id="fake-user-2",
    )

    resp = client.delete(
        "/fake/social-accounts", headers={"Authorization": "Bearer test"}
    )

    assert resp.status_code == 400
    assert resp.json() == {
        "error": "multiple_accounts_connected",
        "error_description": (
            "Multiple fake accounts are connected. "
            "Provide social_account_id to disconnect one."
        ),
    }
    assert accounts_storage.find_social_account_by_id("fake-account-1") is not None
    assert accounts_storage.find_social_account_by_id("fake-account-2") is not None


def test_disconnect_by_id_deletes_selected_account_when_provider_has_multiple_accounts(
    client: TestClient,
    accounts_storage,
):
    _add_social_account(
        accounts_storage,
        account_id="fake-account-1",
        provider_user_id="fake-user-1",
    )
    _add_social_account(
        accounts_storage,
        account_id="fake-account-2",
        provider_user_id="fake-user-2",
    )

    resp = client.delete(
        "/fake/social-accounts/fake-account-2", headers={"Authorization": "Bearer test"}
    )

    assert resp.status_code == 200
    assert accounts_storage.find_social_account_by_id("fake-account-1") is not None
    assert accounts_storage.find_social_account_by_id("fake-account-2") is None


def test_disconnect_rejects_account_for_different_provider(
    client: TestClient,
    accounts_storage,
):
    _add_social_account(
        accounts_storage,
        account_id="other-account",
        provider="other",
        provider_user_id="other-user",
    )

    resp = client.delete(
        "/fake/social-accounts/other-account", headers={"Authorization": "Bearer test"}
    )

    assert resp.status_code == 400
    assert resp.json() == {
        "error": "account_not_connected",
        "error_description": "fake account is not connected",
    }
    assert accounts_storage.find_social_account_by_id("other-account") is not None


def test_disconnect_rejects_account_for_different_user(
    client: TestClient,
    accounts_storage,
    test_password_hash,
):
    accounts_storage.data["other-user"] = DemoUser(
        id="other-user",
        email="other@example.com",
        email_verified=True,
        hashed_password=test_password_hash,
        social_accounts=[],
    )
    _add_social_account(
        accounts_storage,
        user_id="other-user",
        account_id="other-user-fake-account",
    )

    resp = client.delete(
        "/fake/social-accounts/other-user-fake-account",
        headers={"Authorization": "Bearer test"},
    )

    assert resp.status_code == 400
    assert resp.json() == {
        "error": "account_not_connected",
        "error_description": "fake account is not connected",
    }
    assert (
        accounts_storage.find_social_account_by_id("other-user-fake-account")
        is not None
    )


def test_disconnect_blocks_only_login_method(client: TestClient, accounts_storage):
    user = accounts_storage.find_user_by_id("test")
    assert user is not None
    user.hashed_password = cast(str, None)
    _add_social_account(accounts_storage, is_login_method=True)

    resp = client.delete(
        "/fake/social-accounts/fake-account", headers={"Authorization": "Bearer test"}
    )

    assert resp.status_code == 400
    assert resp.json() == {
        "error": "no_alternative_login_method",
        "error_description": "Cannot disconnect fake because it is your only login method.",
    }
    assert accounts_storage.find_social_account_by_id("fake-account") is not None


def test_disconnect_allows_alternative_social_login(
    client: TestClient, accounts_storage
):
    user = accounts_storage.find_user_by_id("test")
    assert user is not None
    user.hashed_password = cast(str, None)
    _add_social_account(accounts_storage, account_id="fake-account", provider="fake")
    _add_social_account(
        accounts_storage,
        account_id="other-account",
        provider="other",
        provider_user_id="other-user",
    )

    resp = client.delete(
        "/fake/social-accounts/fake-account", headers={"Authorization": "Bearer test"}
    )

    assert resp.status_code == 200
    assert accounts_storage.find_social_account_by_id("fake-account") is None
    assert accounts_storage.find_social_account_by_id("other-account") is not None


def test_disconnect_allows_non_login_account_without_password(
    client: TestClient,
    accounts_storage,
):
    user = accounts_storage.find_user_by_id("test")
    assert user is not None
    user.hashed_password = cast(str, None)
    _add_social_account(accounts_storage, is_login_method=False)

    resp = client.delete(
        "/fake/social-accounts/fake-account", headers={"Authorization": "Bearer test"}
    )

    assert resp.status_code == 200
    assert accounts_storage.find_social_account_by_id("fake-account") is None


def test_disconnect_runs_hooks(auth: CrossAuth, accounts_storage):
    _add_social_account(accounts_storage, account_id="hook-account")
    _add_social_account(
        accounts_storage,
        account_id="other-account",
        provider="other",
        provider_user_id="other-user",
    )
    seen: dict[str, str] = {}

    @auth.before("oauth.disconnect")
    async def capture_before(event: BeforeOAuthDisconnectEvent) -> None:
        seen["before_provider"] = event.provider.id
        seen["before_account"] = str(event.social_account.id)

    @auth.after("oauth.disconnect")
    async def capture_after(event: AfterOAuthDisconnectEvent) -> None:
        seen["after_provider"] = event.provider.id
        seen["after_account"] = str(event.social_account.id)

    app = FastAPI()
    app.include_router(auth.router)

    with TestClient(app) as client:
        resp = client.delete(
            "/fake/social-accounts/hook-account",
            headers={"Authorization": "Bearer test"},
        )

    assert resp.status_code == 200
    assert seen == {
        "before_provider": "fake",
        "before_account": "hook-account",
        "after_provider": "fake",
        "after_account": "hook-account",
    }


def test_disconnect_before_hook_can_block(auth: CrossAuth, accounts_storage):
    _add_social_account(accounts_storage, account_id="blocked-account")
    seen = {"after": False}

    @auth.before("oauth.disconnect")
    async def block_disconnect(event: BeforeOAuthDisconnectEvent) -> None:
        raise CrossAuthException("disconnect_disabled", "Disconnect disabled")

    @auth.after("oauth.disconnect")
    async def capture_after(event: AfterOAuthDisconnectEvent) -> None:
        seen["after"] = True

    app = FastAPI()
    app.include_router(auth.router)

    with TestClient(app) as client:
        resp = client.delete(
            "/fake/social-accounts/blocked-account",
            headers={"Authorization": "Bearer test"},
        )

    assert resp.status_code == 400
    assert resp.json() == {
        "error": "disconnect_disabled",
        "error_description": "Disconnect disabled",
    }
    assert accounts_storage.find_social_account_by_id("blocked-account") is not None
    assert seen == {"after": False}
