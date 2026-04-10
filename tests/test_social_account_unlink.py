import pytest
from cross_auth._context import Context
from cross_auth._social_accounts import unlink_social_account
from cross_auth._storage import AccountsStorage, User
from cross_web import AsyncHTTPRequest, TestingRequestAdapter

pytestmark = pytest.mark.asyncio


def _make_request(
    social_account_id: str,
    *,
    authenticated: bool,
) -> AsyncHTTPRequest:
    headers = {"Authorization": "Bearer test"} if authenticated else {}

    request = AsyncHTTPRequest(
        TestingRequestAdapter(
            method="DELETE",
            path_params={"social_account_id": social_account_id},
            url=f"http://localhost:8000/social-accounts/{social_account_id}",
            headers=headers,
        )
    )
    return request


async def test_unlink_requires_authentication(
    context: Context,
) -> None:
    response = await unlink_social_account(
        _make_request("social-account-id", authenticated=False),
        context,
    )

    assert response.status_code == 401
    assert response.json() == {
        "error": "unauthorized",
        "error_description": "Not logged in",
    }


async def test_unlink_fails_when_account_is_not_linked(
    context: Context,
) -> None:
    response = await unlink_social_account(
        _make_request("missing-account", authenticated=True),
        context,
    )

    assert response.status_code == 404
    assert response.json() == {
        "error": "account_not_linked",
        "error_description": "Social account not found",
    }


async def test_unlink_deletes_social_account(
    context: Context,
    accounts_storage: AccountsStorage,
    logged_in_user: User,
) -> None:
    social_account = accounts_storage.create_social_account(
        user_id=logged_in_user.id,
        provider="test",
        provider_user_id="provider-user-id",
        access_token=None,
        refresh_token=None,
        access_token_expires_at=None,
        refresh_token_expires_at=None,
        scope=None,
        user_info={"id": "provider-user-id"},
        provider_email=logged_in_user.email,
        provider_email_verified=True,
        is_login_method=True,
    )

    response = await unlink_social_account(
        _make_request(str(social_account.id), authenticated=True),
        context,
    )

    assert response.status_code == 200
    assert response.json() == {"message": "Account unlinked"}
    assert not list(logged_in_user.social_accounts)


async def test_unlink_blocks_only_remaining_login_method(
    context: Context,
    accounts_storage: AccountsStorage,
    logged_in_user: User,
) -> None:
    logged_in_user.hashed_password = None
    social_account = accounts_storage.create_social_account(
        user_id=logged_in_user.id,
        provider="test",
        provider_user_id="provider-user-id",
        access_token=None,
        refresh_token=None,
        access_token_expires_at=None,
        refresh_token_expires_at=None,
        scope=None,
        user_info={"id": "provider-user-id"},
        provider_email=logged_in_user.email,
        provider_email_verified=True,
        is_login_method=True,
    )

    response = await unlink_social_account(
        _make_request(str(social_account.id), authenticated=True),
        context,
    )

    assert response.status_code == 400
    assert response.json() == {
        "error": "last_login_method",
        "error_description": "Cannot unlink the only remaining login method",
    }
    assert len(list(logged_in_user.social_accounts)) == 1


async def test_unlink_allows_non_login_method_without_alternative(
    context: Context,
    accounts_storage: AccountsStorage,
    logged_in_user: User,
) -> None:
    logged_in_user.hashed_password = None
    social_account = accounts_storage.create_social_account(
        user_id=logged_in_user.id,
        provider="test",
        provider_user_id="provider-user-id",
        access_token=None,
        refresh_token=None,
        access_token_expires_at=None,
        refresh_token_expires_at=None,
        scope=None,
        user_info={"id": "provider-user-id"},
        provider_email=logged_in_user.email,
        provider_email_verified=True,
        is_login_method=False,
    )

    response = await unlink_social_account(
        _make_request(str(social_account.id), authenticated=True),
        context,
    )

    assert response.status_code == 200
    assert response.json() == {"message": "Account unlinked"}
    assert not list(logged_in_user.social_accounts)


async def test_unlink_targets_the_requested_account(
    context: Context,
    accounts_storage: AccountsStorage,
    logged_in_user: User,
) -> None:
    first_account = accounts_storage.create_social_account(
        user_id=logged_in_user.id,
        provider="test",
        provider_user_id="provider-user-id-1",
        access_token=None,
        refresh_token=None,
        access_token_expires_at=None,
        refresh_token_expires_at=None,
        scope=None,
        user_info={"id": "provider-user-id-1"},
        provider_email=logged_in_user.email,
        provider_email_verified=True,
        is_login_method=True,
    )
    second_account = accounts_storage.create_social_account(
        user_id=logged_in_user.id,
        provider="test",
        provider_user_id="provider-user-id-2",
        access_token=None,
        refresh_token=None,
        access_token_expires_at=None,
        refresh_token_expires_at=None,
        scope=None,
        user_info={"id": "provider-user-id-2"},
        provider_email=logged_in_user.email,
        provider_email_verified=True,
        is_login_method=True,
    )

    response = await unlink_social_account(
        _make_request(str(second_account.id), authenticated=True),
        context,
    )

    assert response.status_code == 200
    assert [account.id for account in logged_in_user.social_accounts] == [first_account.id]


async def test_unlink_rejects_accounts_owned_by_another_user(
    context: Context,
    accounts_storage: AccountsStorage,
) -> None:
    other_user = accounts_storage.create_user(
        user_info={"id": "other-user"},
        email="other@example.com",
        email_verified=True,
    )
    social_account = accounts_storage.create_social_account(
        user_id=other_user.id,
        provider="test",
        provider_user_id="provider-user-id",
        access_token=None,
        refresh_token=None,
        access_token_expires_at=None,
        refresh_token_expires_at=None,
        scope=None,
        user_info={"id": "provider-user-id"},
        provider_email=other_user.email,
        provider_email_verified=True,
        is_login_method=True,
    )

    response = await unlink_social_account(
        _make_request(str(social_account.id), authenticated=True),
        context,
    )

    assert response.status_code == 404
    assert response.json() == {
        "error": "account_not_linked",
        "error_description": "Social account not found",
    }
    assert len(list(other_user.social_accounts)) == 1


async def test_unlink_runs_post_unlink_hook(
    context: Context,
    accounts_storage: AccountsStorage,
    logged_in_user: User,
) -> None:
    social_account = accounts_storage.create_social_account(
        user_id=logged_in_user.id,
        provider="test",
        provider_user_id="provider-user-id",
        access_token=None,
        refresh_token=None,
        access_token_expires_at=None,
        refresh_token_expires_at=None,
        scope=None,
        user_info={"id": "provider-user-id"},
        provider_email=logged_in_user.email,
        provider_email_verified=True,
        is_login_method=True,
    )
    calls: list[tuple[str, str]] = []

    async def hook(
        request: AsyncHTTPRequest,
        hook_context: Context,
        user: User,
        unlinked_social_account,
    ) -> None:
        assert hook_context is context
        calls.append((user.id, unlinked_social_account.id))

    context.on_social_account_unlinked = hook

    response = await unlink_social_account(
        _make_request(str(social_account.id), authenticated=True),
        context,
    )

    assert response.status_code == 200
    assert calls == [(logged_in_user.id, social_account.id)]


async def test_unlink_ignores_post_unlink_hook_failures(
    context: Context,
    accounts_storage: AccountsStorage,
    logged_in_user: User,
) -> None:
    social_account = accounts_storage.create_social_account(
        user_id=logged_in_user.id,
        provider="test",
        provider_user_id="provider-user-id",
        access_token=None,
        refresh_token=None,
        access_token_expires_at=None,
        refresh_token_expires_at=None,
        scope=None,
        user_info={"id": "provider-user-id"},
        provider_email=logged_in_user.email,
        provider_email_verified=True,
        is_login_method=True,
    )

    async def hook(
        request: AsyncHTTPRequest,
        hook_context: Context,
        user: User,
        unlinked_social_account,
    ) -> None:
        raise RuntimeError("boom")

    context.on_social_account_unlinked = hook

    response = await unlink_social_account(
        _make_request(str(social_account.id), authenticated=True),
        context,
    )

    assert response.status_code == 200
    assert response.json() == {"message": "Account unlinked"}
    assert not list(logged_in_user.social_accounts)
