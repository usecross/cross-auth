"""Router-level tests for the provider override hooks."""

from __future__ import annotations

from typing import Generator
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import pytest
import respx
from cross_auth._context import Context
from cross_auth._storage import AccountsStorage, SecondaryStorage
from cross_auth.utils._response import Response
from cross_web import AsyncHTTPRequest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from .conftest import (
    FakeProvider,
    _build_auth,
    mock_token_and_userinfo,
    start_provider_auth,
)


def _append_query(url: str, params: dict[str, str]) -> str:
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    for key, value in params.items():
        query[key] = [value]
    return urlunparse(parsed._replace(query=urlencode(query, doseq=True)))


class HookedFakeProvider(FakeProvider):
    def build_authorization_url(
        self,
        state: str,
        redirect_uri: str,
        *,
        request: AsyncHTTPRequest | None = None,
        code_challenge: str | None = None,
        code_challenge_method: str | None = None,
        login_hint: str | None = None,
    ) -> str:
        url = super().build_authorization_url(
            state,
            redirect_uri,
            request=request,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            login_hint=login_hint,
        )
        if request is None or not (audience := request.query_params.get("audience")):
            return url
        return _append_query(url, {"audience": audience})

    async def intercept_callback(
        self,
        request: AsyncHTTPRequest,
        context: Context,
    ) -> Response | None:
        if request.query_params.get("provider_status") == "pending":
            return Response(
                status_code=302,
                headers={"Location": "/oauth/pending?provider=fake"},
            )
        return None

    async def finalize_redirect(
        self,
        request: AsyncHTTPRequest,
        response: Response,
    ) -> Response:
        if (
            request.query_params.get("include_provider") == "true"
            and response.status_code == 302
            and response.headers
            and (location := response.headers.get("Location"))
        ):
            new_headers = dict(response.headers)
            new_headers["Location"] = _append_query(location, {"provider": self.id})
            return Response(
                status_code=302,
                body=response.body,
                cookies=response.cookies,
                headers=new_headers,
            )
        return response


@pytest.fixture
def hooked_provider() -> HookedFakeProvider:
    return HookedFakeProvider(client_id="fake-client-id", client_secret="fake-secret")


@pytest.fixture
def client(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    hooked_provider: HookedFakeProvider,
) -> Generator[TestClient, None, None]:
    auth = _build_auth(
        storage=secondary_storage,
        accounts_storage=accounts_storage,
        providers=[hooked_provider],
    )
    app = FastAPI()
    app.include_router(auth.router)
    with TestClient(app, follow_redirects=False) as c:
        yield c


def test_build_authorization_url_receives_request(client: TestClient):
    resp, _ = start_provider_auth(
        client,
        "/fake/login",
        params={"audience": "internal"},
    )

    query = parse_qs(urlparse(resp.headers["location"]).query)
    assert query["audience"] == ["internal"]


def test_build_authorization_url_default_branch_unaffected(client: TestClient):
    resp, _ = start_provider_auth(client, "/fake/login")
    query = parse_qs(urlparse(resp.headers["location"]).query)
    assert "audience" not in query


def test_intercept_callback_short_circuits_callback(client: TestClient):
    resp = client.get(
        "/fake/callback",
        params={"provider_status": "pending"},
    )
    assert resp.status_code == 302
    assert resp.headers["location"] == "/oauth/pending?provider=fake"


@respx.mock
def test_finalize_redirect_can_rewrite_session_redirect(
    client: TestClient,
):
    mock_token_and_userinfo(email="alice@example.com")

    _, state = start_provider_auth(client, "/fake/login", params={"next": "/dashboard"})

    resp = client.get(
        "/fake/callback",
        params={
            "code": "provider-code",
            "state": state,
            "include_provider": "true",
        },
    )
    assert resp.status_code == 302

    location = resp.headers["location"]
    parsed = urlparse(location)
    assert parsed.path == "/dashboard"
    assert parse_qs(parsed.query) == {"provider": ["fake"]}


@respx.mock
def test_finalize_redirect_noop_by_default(client: TestClient):
    mock_token_and_userinfo(email="alice@example.com")

    _, state = start_provider_auth(client, "/fake/login", params={"next": "/dashboard"})

    resp = client.get(
        "/fake/callback",
        params={"code": "provider-code", "state": state},
    )
    assert resp.status_code == 302
    assert resp.headers["location"] == "/dashboard"
