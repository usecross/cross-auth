"""Router-level tests for the link flow: POST /{provider}/link + /finalize-link."""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import respx
from fastapi import FastAPI
from fastapi.testclient import TestClient

from cross_auth._auth_flow import LinkCodeData
from cross_auth._storage import SecondaryStorage

from .conftest import load_auth_request, mock_token_and_userinfo


_LINK_CODE_CHALLENGE = "n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg"
_LINK_CODE_VERIFIER = "test"  # matches the challenge above


def _auth_enabled_client(build_auth) -> TestClient:
    auth = build_auth(config={"account_linking": {"enabled": True}})
    app = FastAPI()
    app.include_router(auth.router)
    return TestClient(app, follow_redirects=False)


def test_link_requires_authentication(build_auth):
    c = _auth_enabled_client(build_auth)
    resp = c.post(
        "/fake/link",
        json={
            "redirect_uri": "http://client.example/cb",
            "code_challenge": _LINK_CODE_CHALLENGE,
            "code_challenge_method": "S256",
            "client_id": "app-client",
        },
    )
    assert resp.status_code == 401
    assert resp.json()["error"] == "unauthorized"


def test_link_requires_linking_enabled(build_auth):
    # Default auth has linking disabled in config.
    auth = build_auth()
    app = FastAPI()
    app.include_router(auth.router)
    with TestClient(app, follow_redirects=False) as c:
        resp = c.post(
            "/fake/link",
            headers={"Authorization": "Bearer test"},
            json={
                "redirect_uri": "http://client.example/cb",
                "code_challenge": _LINK_CODE_CHALLENGE,
                "code_challenge_method": "S256",
                "client_id": "app-client",
            },
        )
    assert resp.status_code == 400
    assert resp.json()["error"] == "linking_disabled"


def test_link_returns_authorization_url_and_stores_request(
    build_auth, secondary_storage: SecondaryStorage
):
    with _auth_enabled_client(build_auth) as c:
        resp = c.post(
            "/fake/link",
            headers={"Authorization": "Bearer test"},
            json={
                "redirect_uri": "http://client.example/cb",
                "code_challenge": _LINK_CODE_CHALLENGE,
                "code_challenge_method": "S256",
                "client_id": "app-client",
                "state": "client-state",
            },
        )

    assert resp.status_code == 200
    body = resp.json()
    authorization_url = body["authorization_url"]
    assert authorization_url.startswith("https://fake.example/oauth/authorize")

    qs = parse_qs(urlparse(authorization_url).query)
    state = qs["state"][0]

    auth_req = load_auth_request(secondary_storage, state)
    assert auth_req.flow == "link"
    assert auth_req.user_id == "test"
    assert auth_req.client_id == "app-client"
    assert auth_req.client_redirect_uri == "http://client.example/cb"
    assert auth_req.client_state == "client-state"


@respx.mock
def test_link_callback_stores_link_code(
    build_auth, secondary_storage: SecondaryStorage
):
    with _auth_enabled_client(build_auth) as c:
        resp = c.post(
            "/fake/link",
            headers={"Authorization": "Bearer test"},
            json={
                "redirect_uri": "http://client.example/cb",
                "code_challenge": _LINK_CODE_CHALLENGE,
                "code_challenge_method": "S256",
                "client_id": "app-client",
            },
        )
        qs = parse_qs(urlparse(resp.json()["authorization_url"]).query)
        state = qs["state"][0]

        callback_resp = c.get(
            "/fake/callback",
            params={"code": "provider-code", "state": state},
        )

    assert callback_resp.status_code == 302
    client_redirect = urlparse(callback_resp.headers["location"])
    assert client_redirect.path == "/cb"
    link_code = parse_qs(client_redirect.query)["link_code"][0]

    raw = secondary_storage.get(f"oauth:link_request:{link_code}")
    assert raw is not None
    link_data = LinkCodeData.model_validate_json(raw)
    assert link_data.user_id == "test"
    assert link_data.provider_code == "provider-code"


@respx.mock
def test_finalize_link_creates_social_account(build_auth, accounts_storage):
    mock_token_and_userinfo(email="test@example.com", provider_user_id="linked-id")

    with _auth_enabled_client(build_auth) as c:
        start = c.post(
            "/fake/link",
            headers={"Authorization": "Bearer test"},
            json={
                "redirect_uri": "http://client.example/cb",
                "code_challenge": _LINK_CODE_CHALLENGE,
                "code_challenge_method": "S256",
                "client_id": "app-client",
            },
        )
        state = parse_qs(urlparse(start.json()["authorization_url"]).query)["state"][0]

        callback = c.get(
            "/fake/callback", params={"code": "provider-code", "state": state}
        )
        link_code = parse_qs(urlparse(callback.headers["location"]).query)["link_code"][
            0
        ]

        finalize = c.post(
            "/fake/finalize-link",
            headers={"Authorization": "Bearer test"},
            json={
                "link_code": link_code,
                "code_verifier": _LINK_CODE_VERIFIER,
            },
        )

    assert finalize.status_code == 200
    user = accounts_storage.find_user_by_email("test@example.com")
    assert user is not None
    social = [a for a in user.social_accounts if a.provider == "fake"]
    assert len(social) == 1
    assert social[0].provider_user_id == "linked-id"
    # Default `allow_login=False` — linked account shouldn't be a login method.
    assert social[0].is_login_method is False


def test_finalize_link_requires_authentication(build_auth):
    with _auth_enabled_client(build_auth) as c:
        resp = c.post(
            "/fake/finalize-link",
            json={"link_code": "anything", "code_verifier": _LINK_CODE_VERIFIER},
        )
    assert resp.status_code == 401
