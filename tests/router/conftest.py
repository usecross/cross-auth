from __future__ import annotations

from typing import Any, Generator
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import respx
from cross_web import AsyncHTTPRequest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from cross_auth._auth_flow import AuthRequest
from cross_auth._config import Config
from cross_auth._storage import AccountsStorage, SecondaryStorage, User
from cross_auth.fastapi import CrossAuth
from cross_auth.social_providers.oauth import OAuth2Provider


class FakeProvider(OAuth2Provider):
    """A minimal provider stand-in for router integration tests."""

    id = "fake"
    authorization_endpoint = "https://fake.example/oauth/authorize"
    token_endpoint = "https://fake.example/oauth/token"
    user_info_endpoint = "https://fake.example/user"
    scopes = ["email"]
    supports_pkce = True


@pytest.fixture
def fake_provider() -> FakeProvider:
    return FakeProvider(client_id="fake-client-id", client_secret="fake-secret")


def _bearer_user_resolver(
    accounts_storage: AccountsStorage,
) -> "Any":
    """Resolve a user from an `Authorization: Bearer <user_id>` header.

    Tests authenticate by sending `Authorization: Bearer test`, which refers to
    the seeded test user in `tests/conftest.py`.
    """

    def resolve(request: AsyncHTTPRequest) -> User | None:
        auth_header = request.headers.get("Authorization") or request.headers.get(
            "authorization"
        )
        if not auth_header or not auth_header.startswith("Bearer "):
            return None
        user_id = auth_header.removeprefix("Bearer ").strip()
        return accounts_storage.find_user_by_id(user_id)

    return resolve


def _build_auth(
    *,
    storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    providers: list[OAuth2Provider],
    trusted_origins: list[str] | None = None,
    config: Config | None = None,
    default_next_url: str = "/",
) -> CrossAuth:
    return CrossAuth(
        providers=providers,
        storage=storage,
        accounts_storage=accounts_storage,
        create_token=lambda user_id: (f"token-{user_id}", 0),
        trusted_origins=trusted_origins or ["client.example"],
        config=config,
        default_next_url=default_next_url,
        get_user_from_request=_bearer_user_resolver(accounts_storage),
    )


@pytest.fixture
def auth(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    fake_provider: FakeProvider,
) -> CrossAuth:
    return _build_auth(
        storage=secondary_storage,
        accounts_storage=accounts_storage,
        providers=[fake_provider],
    )


@pytest.fixture
def build_auth(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    fake_provider: FakeProvider,
):
    def _make(**overrides: Any) -> CrossAuth:
        return _build_auth(
            storage=secondary_storage,
            accounts_storage=accounts_storage,
            providers=[fake_provider],
            **overrides,
        )

    return _make


@pytest.fixture
def client(auth: CrossAuth) -> Generator[TestClient, None, None]:
    app = FastAPI()
    app.include_router(auth.router)
    with TestClient(app, follow_redirects=False) as c:
        yield c


def start_provider_auth(
    client: TestClient,
    path: str,
    params: dict[str, str] | None = None,
) -> tuple[httpx.Response, str]:
    """Send a request that kicks off a provider flow and return (response, state)."""
    resp = client.get(path, params=params)
    assert resp.status_code == 302, resp.text
    location = resp.headers["location"]
    qs = parse_qs(urlparse(location).query)
    return resp, qs["state"][0]


def load_auth_request(storage: SecondaryStorage, state: str) -> AuthRequest:
    raw = storage.get(f"oauth:authorization_request:{state}")
    assert raw is not None, f"no auth request stored for state={state}"
    return AuthRequest.model_validate_json(raw)


def mock_token_and_userinfo(
    *,
    email: str = "alice@example.com",
    provider_user_id: str = "fake-user-1",
    email_verified: bool = True,
) -> None:
    """Register respx mocks for token + userinfo. Call inside @respx.mock context."""
    respx.post("https://fake.example/oauth/token").mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "provider-access-token",
                "token_type": "Bearer",
                "scope": "email",
            },
        )
    )
    respx.get("https://fake.example/user").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": provider_user_id,
                "email": email,
                "email_verified": email_verified,
            },
        )
    )
