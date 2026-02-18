from collections.abc import Callable
from datetime import datetime, timezone

import httpx
import pytest
import respx
import time_machine
from cross_web import AsyncHTTPRequest, TestingRequestAdapter
from inline_snapshot import snapshot
from respx import MockRouter

from cross_auth._context import Context, SecondaryStorage
from cross_auth._storage import AccountsStorage, User
from cross_auth.social_providers.github import GitHubProvider
from tests.conftest import MemoryAccountsStorage

pytestmark = pytest.mark.asyncio


class MockGithubProvider(GitHubProvider):
    def _generate_code(self) -> str:
        return "a-totally-valid-code"


MockGithubFactory = Callable[..., MockGithubProvider]


@pytest.fixture
def mock_github(respx_mock: MockRouter) -> MockGithubFactory:
    """Factory that creates a MockGithubProvider and wires up respx mocks."""

    def _create(
        *,
        allow_noreply_emails: bool = False,
        user_id: str = "pollo",
        name: str = "Pollo",
        emails: list[dict] | None = None,
    ) -> MockGithubProvider:
        provider = MockGithubProvider(
            client_id="test_client_id",
            client_secret="test_client_secret",
            allow_noreply_emails=allow_noreply_emails,
        )
        if emails is None:
            emails = [{"email": "pollo@example.com", "primary": True, "verified": True}]

        respx_mock.post(provider.token_endpoint).mock(
            return_value=httpx.Response(
                status_code=200,
                json={
                    "access_token": "test_access_token",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "scope": "openid email profile",
                },
            )
        )
        respx_mock.get(provider.user_info_endpoint).mock(
            return_value=httpx.Response(
                status_code=200, json={"id": user_id, "name": name}
            )
        )
        respx_mock.get(provider.emails_endpoint).mock(
            return_value=httpx.Response(status_code=200, json=emails)
        )
        return provider

    return _create


@respx.mock
async def test_callback_signup_with_verified_primary(
    context: Context,
    mock_github: MockGithubFactory,
    valid_callback_request: AsyncHTTPRequest,
    accounts_storage: MemoryAccountsStorage,
):
    provider = mock_github()

    response = await provider.callback(valid_callback_request, context)

    assert response.status_code == 302
    assert response.headers is not None
    assert response.headers["Location"] == snapshot(
        "http://valid-frontend.com/callback?code=a-totally-valid-code&state=test_client_state"
    )

    account = accounts_storage.find_user_by_email("pollo@example.com")
    assert account is not None
    assert account.email == "pollo@example.com"


@respx.mock
async def test_callback_rejects_noreply_email_by_default(
    context: Context,
    mock_github: MockGithubFactory,
    valid_callback_request: AsyncHTTPRequest,
):
    provider = mock_github(
        emails=[
            {
                "email": "123+user@users.noreply.github.com",
                "primary": True,
                "verified": True,
            }
        ],
    )

    response = await provider.callback(valid_callback_request, context)

    assert response.status_code == 302
    assert response.headers is not None
    assert "error=no_verified_email" in response.headers["Location"]


@respx.mock
async def test_callback_allows_noreply_when_configured(
    context: Context,
    mock_github: MockGithubFactory,
    valid_callback_request: AsyncHTTPRequest,
    accounts_storage: MemoryAccountsStorage,
):
    provider = mock_github(
        allow_noreply_emails=True,
        emails=[
            {
                "email": "123+user@users.noreply.github.com",
                "primary": True,
                "verified": True,
            }
        ],
    )

    response = await provider.callback(valid_callback_request, context)

    assert response.status_code == 302
    assert "error" not in (response.headers or {}).get("Location", "")

    account = accounts_storage.find_user_by_email("123+user@users.noreply.github.com")
    assert account is not None


@time_machine.travel(datetime(2012, 10, 1, 1, 0, tzinfo=timezone.utc), tick=False)
@respx.mock
async def test_finalize_link_uses_login_rules(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    logged_in_user: User,
    mock_github: MockGithubFactory,
    valid_link_code: str,
) -> None:
    """finalize_link should pass is_login=True and the user's stored email."""

    def _get_user_from_request(request: AsyncHTTPRequest) -> User | None:
        if request.headers.get("Authorization") == "Bearer test":
            return logged_in_user
        return None

    link_context = Context(
        secondary_storage=secondary_storage,
        accounts_storage=accounts_storage,
        create_token=lambda id: (f"token-{id}", 0),
        get_user_from_request=_get_user_from_request,
        trusted_origins=["valid-frontend.com"],
        config={"account_linking": {"enabled": True}},
    )

    provider = mock_github(
        user_id="new_github_user",
        emails=[
            {"email": "test@example.com", "primary": True, "verified": True},
        ],
    )

    response = await provider.finalize_link(
        AsyncHTTPRequest(
            TestingRequestAdapter(
                method="POST",
                url="http://localhost:8000/test/finalize-link",
                json={
                    "link_code": valid_link_code,
                    "code_verifier": "test",
                },
                headers={"Authorization": "Bearer test"},
            )
        ),
        link_context,
    )

    assert response.status_code == 200
