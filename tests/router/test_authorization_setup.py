"""Common attempt setup must not merge the policies of the individual flows."""

import hashlib
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

import pytest
import respx
import time_machine
from fastapi import FastAPI
from fastapi.testclient import TestClient

from cross_auth.utils._pkce import calculate_s256_challenge

from .conftest import load_auth_request, mock_token_and_userinfo

NOW = datetime(2026, 9, 17, tzinfo=timezone.utc)
VERIFIER = "application-code-verifier"


def _start(client: TestClient, flow: str):
    if flow == "link":
        response = client.post(
            "/auth/fake/link",
            headers={"Authorization": "Bearer test"},
            json={
                "client_id": "app-client",
                "redirect_uri": "http://client.example/cb",
                "state": "client-state",
                "code_challenge": calculate_s256_challenge(VERIFIER),
                "code_challenge_method": "S256",
            },
        )
        assert response.status_code == 200
        url = response.json()["authorization_url"]
    else:
        path = {"session": "login", "connect": "connect", "token": "authorize"}[flow]
        response = client.get(
            f"/auth/fake/{path}",
            headers={"Authorization": "Bearer test"},
            params={
                "client_id": "app-client",
                "redirect_uri": "http://client.example/cb",
                "state": "client-state",
                "response_type": "code",
                "code_challenge": calculate_s256_challenge(VERIFIER),
                "code_challenge_method": "S256",
                "login_hint": "hint@example.com",
                "next": "/profile",
            },
        )
        assert response.status_code == 302
        url = response.headers["location"]
    return response, parse_qs(urlparse(url).query)


def _app(build_auth):
    auth = build_auth(
        config={
            "session": {"cookies": {"auth": True}},
            "account_linking": {"enabled": True},
        }
    )
    app = FastAPI()
    app.include_router(auth.router, prefix="/auth")
    return app


@pytest.mark.parametrize("flow", ["session", "connect", "token", "link"])
@pytest.mark.parametrize("supports_pkce", [False, True])
@time_machine.travel(NOW, tick=False)
def test_each_flow_stores_a_fresh_browser_bound_provider_attempt(
    build_auth, fake_provider, secondary_storage, monkeypatch, flow, supports_pkce
):
    fake_provider.supports_pkce = supports_pkce
    monkeypatch.setattr(
        fake_provider, "get_authorization_data", lambda: {"nonce": "managed-nonce"}
    )
    states: set[str] = set()
    with TestClient(_app(build_auth), follow_redirects=False) as client:
        for _ in range(2):
            response, query = _start(client, flow)
            state = query["state"][0]
            assert state not in states
            states.add(state)
            stored = load_auth_request(secondary_storage, state)
            assert stored.flow == flow
            assert stored.provider_id == "fake"
            assert stored.provider_data == {"nonce": "managed-nonce"}
            assert stored.expires_at == NOW + timedelta(minutes=10)
            binding = response.cookies[f"cross_auth_oauth_{state}"]
            assert (
                stored.browser_binding == hashlib.sha256(binding.encode()).hexdigest()
            )
            assert query["redirect_uri"] == ["http://testserver/auth/fake/callback"]
            if supports_pkce:
                assert stored.provider_code_verifier is not None
                assert query["code_challenge"] == [
                    calculate_s256_challenge(stored.provider_code_verifier)
                ]
                assert query["code_challenge_method"] == ["S256"]
            else:
                assert stored.provider_code_verifier is None
                assert "code_challenge" not in query
                assert "code_challenge_method" not in query
            if flow in {"session", "token"}:
                assert query["login_hint"] == ["hint@example.com"]
            else:
                assert "login_hint" not in query
            if flow in {"session", "connect"}:
                assert stored.next_url == "/profile"
            else:
                assert stored.client_state == "client-state"
                assert stored.client_code_challenge == calculate_s256_challenge(
                    VERIFIER
                )


@pytest.mark.parametrize("flow", ["connect", "link"])
@respx.mock
def test_connection_and_link_keep_distinct_email_policy(
    build_auth, accounts_storage, flow
):
    mock_token_and_userinfo(email="test@example.com", email_verified=False)
    with TestClient(_app(build_auth), follow_redirects=False) as client:
        _, query = _start(client, flow)
        callback = client.get(
            "/auth/fake/callback",
            headers={"Authorization": "Bearer test"},
            params={"state": query["state"][0], "code": "provider-code"},
        )
        if flow == "connect":
            assert callback.status_code == 302
            assert callback.headers["location"] == "/profile"
        else:
            link_code = parse_qs(urlparse(callback.headers["location"]).query)[
                "link_code"
            ][0]
            response = client.post(
                "/auth/fake/finalize-link",
                headers={"Authorization": "Bearer test"},
                json={
                    "link_code": link_code,
                    "code_verifier": VERIFIER,
                    "allow_login": False,
                },
            )
            assert response.status_code == 400
            assert response.json()["error"] == "email_not_verified"
    accounts = accounts_storage.list_social_accounts(user_id="test")
    if flow == "connect":
        assert len(accounts) == 1
        assert accounts[0].is_login_method is False
        assert accounts[0].provider_email_verified is False
    else:
        assert accounts == []
