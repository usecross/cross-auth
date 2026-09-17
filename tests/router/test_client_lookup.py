"""Applications can resolve current OAuth registrations from ordinary storage."""

import sqlite3
from urllib.parse import parse_qs, urlparse

import pytest
import respx
from fastapi import FastAPI
from fastapi.testclient import TestClient

from cross_auth import OAuthClient

from .conftest import mock_token_and_userinfo
from .test_link_flow import _LINK_CODE_CHALLENGE, _LINK_CODE_VERIFIER

CLIENT_ID = "dashboard"
REDIRECT = "https://dashboard.example/callback"


def _browser(build_auth, resolver):
    auth = build_auth(
        get_client=resolver,
        config={"account_linking": {"enabled": True, "allow_different_emails": True}},
    )
    app = FastAPI()
    app.include_router(auth.router)
    return auth, TestClient(app, follow_redirects=False)


def _start(client, flow="token", redirect=REDIRECT, client_id=CLIENT_ID):
    parameters = {
        "client_id": client_id,
        "redirect_uri": redirect,
        "code_challenge": _LINK_CODE_CHALLENGE,
        "code_challenge_method": "S256",
    }
    if flow == "link":
        return client.post(
            "/fake/link", json=parameters, headers={"Authorization": "Bearer test"}
        )
    return client.get("/fake/authorize", params={**parameters, "response_type": "code"})


def _callback(client, start_response, flow="token"):
    location = (
        start_response.json()["authorization_url"]
        if flow == "link"
        else start_response.headers["location"]
    )
    state = parse_qs(urlparse(location).query)["state"][0]
    return client.get(
        "/fake/callback", params={"state": state, "code": "provider-code"}
    )


def _redeem(client, callback, boundary, redirect=REDIRECT):
    params = parse_qs(urlparse(callback.headers["location"]).query)
    if boundary == "link":
        return client.post(
            "/fake/finalize-link",
            headers={"Authorization": "Bearer test"},
            json={
                "link_code": params["link_code"][0],
                "code_verifier": _LINK_CODE_VERIFIER,
            },
        )
    return client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "redirect_uri": redirect,
            "code": params["code"][0],
            "code_verifier": _LINK_CODE_VERIFIER,
        },
    )


@pytest.mark.parametrize("flow", ["token", "link"])
def test_dictionary_client_lookup_receives_client_id_and_rejects_unknown(
    build_auth, flow
):
    clients = {CLIENT_ID: OAuthClient(client_id=CLIENT_ID, redirect_uris=(REDIRECT,))}
    looked_up = []

    def lookup(client_id):
        looked_up.append(client_id)
        return clients.get(client_id)

    _, client = _browser(build_auth, lookup)
    with client:
        accepted = _start(client, flow)
        assert accepted.status_code == (200 if flow == "link" else 302)
        assert looked_up and set(looked_up) == {CLIENT_ID}

        looked_up.clear()
        rejected = _start(client, flow, client_id="unknown")

    assert looked_up and set(looked_up) == {"unknown"}
    assert rejected.status_code == 400
    assert "location" not in rejected.headers
    assert "authorization_url" not in rejected.json()


@pytest.fixture
def client_database():
    connection = sqlite3.connect(":memory:", check_same_thread=False)
    connection.execute(
        "CREATE TABLE clients (id TEXT PRIMARY KEY, redirect_uri TEXT NOT NULL)"
    )

    def lookup(client_id):
        row = connection.execute(
            "SELECT id, redirect_uri FROM clients WHERE id = ?", (client_id,)
        ).fetchone()
        return (
            None
            if row is None
            else OAuthClient(client_id=row[0], redirect_uris=(row[1],))
        )

    yield connection, lookup
    connection.close()


@pytest.mark.parametrize("boundary", ["callback", "token", "link"])
@pytest.mark.parametrize("change", ["update", "delete"])
@respx.mock
def test_database_changes_apply_to_pending_attempts_without_rebuilding_auth(
    build_auth, client_database, boundary, change
):
    database, lookup = client_database
    _, client = _browser(build_auth, lookup)
    flow = "link" if boundary == "link" else "token"
    mock_token_and_userinfo(email="test@example.com")

    with client:
        assert _start(client, flow).status_code == 400
        database.execute("INSERT INTO clients VALUES (?, ?)", (CLIENT_ID, REDIRECT))
        database.commit()
        started = _start(client, flow)
        assert started.status_code == (200 if flow == "link" else 302)
        callback = None if boundary == "callback" else _callback(client, started, flow)
        calls_before_change = len(respx.calls)

        if change == "update":
            database.execute(
                "UPDATE clients SET redirect_uri = ? WHERE id = ?",
                ("https://dashboard.example/replacement", CLIENT_ID),
            )
        else:
            database.execute("DELETE FROM clients WHERE id = ?", (CLIENT_ID,))
        database.commit()

        rejected = (
            _callback(client, started, flow)
            if boundary == "callback"
            else _redeem(client, callback, boundary)
        )

    assert rejected.status_code == 400
    assert "location" not in rejected.headers
    assert len(respx.calls) == calls_before_change


def test_mismatched_client_lookup_result_is_a_configuration_error(build_auth):
    auth, _ = _browser(
        build_auth,
        lambda client_id: OAuthClient(
            client_id="different-client", redirect_uris=(REDIRECT,)
        ),
    )

    with pytest.raises(ValueError, match="client"):
        auth._router.context.get_client(CLIENT_ID)


@pytest.mark.parametrize(
    ("registered_redirect", "redirect"),
    [
        ("com.example.app:/callback", "com.example.app:/callback"),
        ("http://127.0.0.1/callback", "http://127.0.0.1:49152/callback"),
        ("http://[::1]/callback", "http://[::1]:49152/callback"),
    ],
)
@respx.mock
def test_native_redirect_completes_token_flow_with_pkce(
    build_auth, registered_redirect, redirect
):
    clients = {
        CLIENT_ID: OAuthClient(
            client_id=CLIENT_ID,
            redirect_uris=(registered_redirect,),
            application_type="native",
        )
    }
    _, client = _browser(build_auth, clients.get)
    mock_token_and_userinfo(email="test@example.com")

    with client:
        started = _start(client, redirect=redirect)
        assert started.status_code == 302
        callback = _callback(client, started)
        assert callback.status_code == 302
        assert callback.headers["location"].startswith(redirect + "?")
        response = _redeem(client, callback, "token", redirect=redirect)

    assert response.status_code == 200
    assert response.json()["access_token"]
    assert response.json()["token_type"].lower() == "bearer"


@respx.mock
def test_native_redemption_requires_the_port_used_to_start_the_attempt(build_auth):
    registration = OAuthClient(
        client_id=CLIENT_ID,
        redirect_uris=("http://127.0.0.1/callback",),
        application_type="native",
    )
    _, client = _browser(build_auth, {CLIENT_ID: registration}.get)
    mock_token_and_userinfo(email="test@example.com")
    redirect = "http://127.0.0.1:49152/callback"

    with client:
        started = _start(client, redirect=redirect)
        callback = _callback(client, started)
        rejected = _redeem(
            client, callback, "token", redirect="http://127.0.0.1:49153/callback"
        )

        assert rejected.status_code == 400
        assert rejected.json()["error"] == "invalid_grant"
        assert rejected.json()["error_description"] == "Redirect URI does not match"
