"""Linking a provider identity to an existing user by email.

The existing user is found by email alone, so the provider must vouch that the
person signing in owns it. Otherwise whoever controls a provider account
claiming that email would get a new login method on the user's account.
"""

from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import respx
from fastapi import FastAPI
from fastapi.testclient import TestClient

from cross_auth._config import Config
from cross_auth.social_providers.discord import DiscordProvider
from cross_auth.social_providers.github import GitHubProvider
from cross_auth.social_providers.oauth import OAuth2Provider

from ..conftest import MemoryAccountsStorage, MemorySessionStorage, MemoryStorage
from .conftest import (
    APP_OAUTH_SERVER,
    FakeProvider,
    _build_auth,
    mock_token_and_userinfo,
    start_provider_auth,
)

EXISTING_EMAIL = "test@example.com"
_CLIENT_PARAMS = {
    "client_id": "app-client",
    "redirect_uri": "http://client.example/cb",
    "state": "client-state",
    "response_type": "code",
    "code_challenge": "client-challenge",
    "code_challenge_method": "S256",
}


def _mock_github(*, email: str, email_verified: bool | None) -> str:
    respx.post("https://github.com/login/oauth/access_token").mock(
        return_value=httpx.Response(
            200, json={"access_token": "gh-access", "token_type": "bearer"}
        )
    )
    respx.get("https://api.github.com/user").mock(
        return_value=httpx.Response(
            200, json={"id": 583231, "login": "octocat", "email": None}
        )
    )
    respx.get("https://api.github.com/user/emails").mock(
        return_value=httpx.Response(
            200,
            json=[{"email": email, "verified": email_verified, "primary": True}],
        )
    )
    return "583231"


def _mock_discord(*, email: str, email_verified: bool | None) -> str:
    respx.post("https://discord.com/api/oauth2/token").mock(
        return_value=httpx.Response(
            200, json={"access_token": "discord-access", "token_type": "Bearer"}
        )
    )
    respx.get("https://discord.com/api/users/@me").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "80351110224678912",
                "username": "nelly",
                "email": email,
                "verified": email_verified,
            },
        )
    )
    return "80351110224678912"


def _mock_fake(*, email: str, email_verified: bool | None) -> str:
    mock_token_and_userinfo(
        email=email, email_verified=email_verified, provider_user_id="fake-user-1"
    )
    return "fake-user-1"


MockProvider = Callable[..., str]
# Each provider with its default settings, and how to mock its responses.
DEFAULT_PROVIDERS: dict[str, tuple[Callable[[], OAuth2Provider], MockProvider]] = {
    "github": (
        lambda: GitHubProvider(client_id="gh-client", client_secret="gh-secret"),
        _mock_github,
    ),
    "discord": (
        lambda: DiscordProvider(client_id="d-client", client_secret="d-secret"),
        _mock_discord,
    ),
    "base": (
        lambda: FakeProvider(client_id="fake-client-id", client_secret="fake-secret"),
        _mock_fake,
    ),
}


def _client(
    provider: OAuth2Provider,
    *,
    secondary_storage: MemoryStorage,
    accounts_storage: MemoryAccountsStorage,
    session_storage: MemorySessionStorage,
    **config: Any,
) -> TestClient:
    full_config: Config = {
        "session": {"cookies": {"auth": True}},
        "account_linking": {"enabled": True},
        **config,
    }
    auth = _build_auth(
        storage=secondary_storage,
        accounts_storage=accounts_storage,
        session_storage=session_storage,
        providers=[provider],
        config=full_config,
        oauth_server=APP_OAUTH_SERVER,
    )
    app = FastAPI()
    app.include_router(auth.router)
    return TestClient(app, follow_redirects=False)


def _sign_in(client: TestClient, provider_id: str, flow: str) -> httpx.Response:
    if flow == "token":
        path, params = f"/{provider_id}/authorize", _CLIENT_PARAMS
    else:
        path, params = f"/{provider_id}/login", None
    _, state = start_provider_auth(client, path, params=params)
    return client.get(
        f"/{provider_id}/callback", params={"code": "provider-code", "state": state}
    )


def _error(response: httpx.Response, flow: str) -> str:
    if flow == "token":
        assert response.status_code == 302
        [error] = parse_qs(urlparse(response.headers["location"]).query)["error"]
        return error
    assert response.status_code == 400
    return response.json()["error"]


def _assert_signed_in(response: httpx.Response, flow: str) -> None:
    assert response.status_code == 302
    if flow == "token":
        query = parse_qs(urlparse(response.headers["location"]).query)
        assert "error" not in query
        assert query["code"]
    else:
        assert "session_id" in response.cookies


@pytest.mark.parametrize("require_verified_email", [False, True])
@pytest.mark.parametrize("flow", ["session", "token"])
@pytest.mark.parametrize("email_verified", [False, None])
@pytest.mark.parametrize("provider_name", list(DEFAULT_PROVIDERS))
@respx.mock
def test_unverified_email_cannot_link_existing_user_by_default(
    provider_name: str,
    email_verified: bool | None,
    flow: str,
    require_verified_email: bool,
    secondary_storage: MemoryStorage,
    accounts_storage: MemoryAccountsStorage,
    session_storage: MemorySessionStorage,
):
    make_provider, mock_provider = DEFAULT_PROVIDERS[provider_name]
    provider = make_provider()
    assert provider.trust_email is False
    mock_provider(email=EXISTING_EMAIL, email_verified=email_verified)

    with _client(
        provider,
        secondary_storage=secondary_storage,
        accounts_storage=accounts_storage,
        session_storage=session_storage,
        require_verified_email=require_verified_email,
    ) as client:
        response = _sign_in(client, provider.id, flow)

    assert _error(response, flow) == "account_not_linked"
    assert list(accounts_storage.data) == ["test"]
    assert accounts_storage.data["test"].social_accounts == []
    assert session_storage.records == {}
    assert "session_id" not in response.cookies
    assert not any(key.startswith("oauth:code:") for key in secondary_storage.data)


@pytest.mark.parametrize("flow", ["session", "token"])
@pytest.mark.parametrize("provider_name", list(DEFAULT_PROVIDERS))
@respx.mock
def test_verified_email_links_existing_user(
    provider_name: str,
    flow: str,
    secondary_storage: MemoryStorage,
    accounts_storage: MemoryAccountsStorage,
    session_storage: MemorySessionStorage,
):
    make_provider, mock_provider = DEFAULT_PROVIDERS[provider_name]
    provider = make_provider()
    provider_user_id = mock_provider(email=EXISTING_EMAIL, email_verified=True)

    with _client(
        provider,
        secondary_storage=secondary_storage,
        accounts_storage=accounts_storage,
        session_storage=session_storage,
        require_verified_email=True,
    ) as client:
        response = _sign_in(client, provider.id, flow)

    _assert_signed_in(response, flow)
    assert list(accounts_storage.data) == ["test"]
    [account] = accounts_storage.data["test"].social_accounts
    assert account.provider == provider.id
    assert account.provider_user_id == provider_user_id
    assert account.provider_email_verified is True
    assert account.is_login_method is True


@pytest.mark.parametrize("flow", ["session", "token"])
@pytest.mark.parametrize("provider_name", list(DEFAULT_PROVIDERS))
@respx.mock
def test_linked_identity_signs_in_whatever_its_email_status(
    provider_name: str,
    flow: str,
    secondary_storage: MemoryStorage,
    accounts_storage: MemoryAccountsStorage,
    session_storage: MemorySessionStorage,
):
    """Sign-in with a linked identity is by subject; the email policy does not apply."""
    make_provider, mock_provider = DEFAULT_PROVIDERS[provider_name]
    provider = make_provider()
    provider_user_id = mock_provider(email=EXISTING_EMAIL, email_verified=False)
    accounts_storage.create_social_account(
        user_id="test",
        provider=provider.id,
        provider_user_id=provider_user_id,
        access_token=None,
        refresh_token=None,
        access_token_expires_at=None,
        refresh_token_expires_at=None,
        scope=None,
        user_info={},
        provider_email=EXISTING_EMAIL,
        provider_email_verified=True,
        is_login_method=True,
    )

    with _client(
        provider,
        secondary_storage=secondary_storage,
        accounts_storage=accounts_storage,
        session_storage=session_storage,
        require_verified_email=True,
    ) as client:
        response = _sign_in(client, provider.id, flow)

    _assert_signed_in(response, flow)
    [account] = accounts_storage.data["test"].social_accounts
    assert account.provider_email_verified is False


@pytest.mark.parametrize(
    ("email_verified", "linked"), [(True, True), (None, True), (False, False)]
)
@respx.mock
def test_trust_email_accepts_only_a_missing_verification_claim(
    email_verified: bool | None,
    linked: bool,
    secondary_storage: MemoryStorage,
    accounts_storage: MemoryAccountsStorage,
    session_storage: MemorySessionStorage,
):
    provider = FakeProvider(
        client_id="fake-client-id", client_secret="fake-secret", trust_email=True
    )
    _mock_fake(email=EXISTING_EMAIL, email_verified=email_verified)

    with _client(
        provider,
        secondary_storage=secondary_storage,
        accounts_storage=accounts_storage,
        session_storage=session_storage,
    ) as client:
        response = _sign_in(client, provider.id, "session")

    if linked:
        _assert_signed_in(response, "session")
        [account] = accounts_storage.data["test"].social_accounts
        assert account.is_login_method is True
    else:
        assert _error(response, "session") == "account_not_linked"
        assert accounts_storage.data["test"].social_accounts == []
        assert session_storage.records == {}


@respx.mock
def test_trust_email_does_not_verify_new_users(
    secondary_storage: MemoryStorage,
    accounts_storage: MemoryAccountsStorage,
    session_storage: MemorySessionStorage,
):
    """require_verified_email still needs email_verified=True to sign up."""
    provider = FakeProvider(
        client_id="fake-client-id", client_secret="fake-secret", trust_email=True
    )
    _mock_fake(email="new@example.com", email_verified=None)

    with _client(
        provider,
        secondary_storage=secondary_storage,
        accounts_storage=accounts_storage,
        session_storage=session_storage,
        require_verified_email=True,
    ) as client:
        response = _sign_in(client, provider.id, "session")

    assert _error(response, "session") == "email_not_verified"
    assert list(accounts_storage.data) == ["test"]
    assert session_storage.records == {}
