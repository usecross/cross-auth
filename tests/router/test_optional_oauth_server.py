"""The opt-in OAuth server (``oauth_server=OAuthServer(...)``).

The OAuth server is the authorization server for registered SPA and native
clients: ``/{provider}/authorize``, ``/token`` and the PKCE
``/{provider}/link`` + ``/{provider}/finalize-link`` pair. It is off by
default; browser sign-in, integration-only connect, disconnect and the
programmatic APIs work without it.
"""

import json
import re
from typing import Annotated, Any
from urllib.parse import parse_qs, urlparse

import pytest
import respx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import Depends, FastAPI
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from cross_auth import OAuthClient, OAuthServer, TokenIssueRequest
from cross_auth._config import Config
from cross_auth._storage import AccountsStorage, SecondaryStorage, User
from cross_auth.fastapi import CrossAuth
from cross_auth.router import AuthRouter
from cross_auth.social_providers.apple import AppleProvider
from cross_auth.social_providers.github import GitHubProvider
from cross_auth.social_providers.google import GoogleProvider
from cross_auth.social_providers.oauth import OAuth2Provider
from cross_auth.utils._pkce import calculate_s256_challenge

from ..conftest import (
    TEST_PASSWORD,
    MemoryAccountsStorage,
    MemorySessionStorage,
    MemoryStorage,
)
from ..django.fake_google import CLIENT_ID, Account, Authorization, FakeGoogle
from .conftest import (
    APP_CLIENT,
    APP_OAUTH_SERVER,
    FakeProvider,
    mock_token_and_userinfo,
    start_provider_auth,
)

VERIFIER = "a" * 64
CLIENT_PARAMS = {
    "client_id": "app-client",
    "redirect_uri": "http://client.example/cb",
    "response_type": "code",
    "code_challenge": calculate_s256_challenge(VERIFIER),
    "code_challenge_method": "S256",
    "state": "client-state",
}

SESSION_ROUTES = {
    ("/{p}/login", "GET"),
    ("/{p}/connect", "GET"),
    ("/{p}/social-accounts", "DELETE"),
    ("/{p}/social-accounts/{social_account_id}", "DELETE"),
    ("/{p}/callback", "GET"),
    ("/{p}/callback", "POST"),
}
OAUTH_SERVER_ROUTES = {
    ("/{p}/authorize", "GET"),
    ("/{p}/link", "POST"),
    ("/{p}/finalize-link", "POST"),
}


def _expected(provider_ids: list[str], *, oauth_server: bool, cookie_auth: bool):
    per_provider = SESSION_ROUTES | (OAUTH_SERVER_ROUTES if oauth_server else set())
    if not cookie_auth:
        per_provider = per_provider - {("/{p}/login", "GET")}
    routes = {
        (path.replace("{p}", provider_id), method)
        for provider_id in provider_ids
        for path, method in per_provider
    }
    return routes | ({("/token", "POST")} if oauth_server else set())


def _route_methods(router: AuthRouter) -> set[tuple[str, str]]:
    return {
        (route.path, method)
        for route in router.routes
        if isinstance(route, APIRoute)
        for method in route.methods
    }


def _missing_refs(schema: dict[str, Any]) -> set[str]:
    refs = set(re.findall(r'"#/components/schemas/([^"]+)"', json.dumps(schema)))
    return refs - set(schema.get("components", {}).get("schemas", {}))


@pytest.fixture
def providers() -> list[OAuth2Provider]:
    return [
        FakeProvider(client_id="fake-client-id", client_secret="fake-secret"),
        GitHubProvider(client_id="github-client-id", client_secret="secret"),
    ]


@pytest.mark.parametrize("cookie_auth", [True, False])
@pytest.mark.parametrize("oauth_server", [True, False])
def test_cross_auth_routes(
    build_auth, providers, oauth_server: bool, cookie_auth: bool
):
    auth = build_auth(
        providers=providers,
        oauth_server=APP_OAUTH_SERVER if oauth_server else None,
        config={"session": {"cookies": {"auth": cookie_auth}}},
    )

    assert _route_methods(auth.router) == _expected(
        ["fake", "github"], oauth_server=oauth_server, cookie_auth=cookie_auth
    )
    assert (auth.router.issuer is None) is not oauth_server
    assert auth.router.issuer is auth._setup.issuer


@pytest.mark.parametrize("cookie_auth", [True, False])
@pytest.mark.parametrize("oauth_server", [True, False])
def test_auth_router_routes(
    secondary_storage,
    accounts_storage,
    session_storage,
    providers,
    oauth_server: bool,
    cookie_auth: bool,
):
    router = AuthRouter(
        providers,
        secondary_storage,
        accounts_storage,
        lambda request: None,
        session_storage=session_storage,
        config={"session": {"cookies": {"auth": cookie_auth}}},
        oauth_server=APP_OAUTH_SERVER if oauth_server else None,
    )

    assert _route_methods(router) == _expected(
        ["fake", "github"], oauth_server=oauth_server, cookie_auth=cookie_auth
    )
    assert (router.issuer is None) is not oauth_server


def test_oauth_server_is_off_by_default(secondary_storage, accounts_storage, providers):
    auth = CrossAuth(
        providers=providers,
        storage=secondary_storage,
        accounts_storage=accounts_storage,
    )
    router = AuthRouter(
        providers=providers,
        secondary_storage=secondary_storage,
        accounts_storage=accounts_storage,
        get_user_from_request=lambda request: None,
    )

    for default in (auth.router, router):
        assert default.issuer is None
        assert default.context.oauth_server is None
        assert _route_methods(default) == _expected(
            ["fake", "github"], oauth_server=False, cookie_auth=False
        )


@pytest.mark.parametrize("name", ["get_client", "token_issuer", "broker"])
def test_oauth_server_options_are_not_constructor_arguments(
    secondary_storage, accounts_storage, name
):
    removed: dict[str, Any] = {name: lambda _: None}

    with pytest.raises(TypeError, match=name):
        CrossAuth(
            providers=[],
            storage=secondary_storage,
            accounts_storage=accounts_storage,
            **removed,
        )
    with pytest.raises(TypeError, match=name):
        AuthRouter(
            providers=[],
            secondary_storage=secondary_storage,
            accounts_storage=accounts_storage,
            get_user_from_request=lambda request: None,
            **removed,
        )


@pytest.mark.parametrize("value", [True, False])
def test_oauth_server_is_not_a_flag(secondary_storage, accounts_storage, value):
    flag: Any = value
    with pytest.raises(TypeError, match="OAuthServer"):
        CrossAuth(
            providers=[],
            storage=secondary_storage,
            accounts_storage=accounts_storage,
            oauth_server=flag,
        )


def test_auth_router_options_are_keyword_only(
    secondary_storage, accounts_storage, session_storage
):
    # 0.38 took token_issuer as the seventh positional argument; later
    # positionals must not slide into its place.
    arguments: list[Any] = [
        [],
        secondary_storage,
        accounts_storage,
        lambda request: None,
        None,
        session_storage,
        lambda request: ("token", 60),
    ]
    with pytest.raises(TypeError, match="positional"):
        AuthRouter(*arguments)


@respx.mock
def test_oauth_server_callbacks_drive_the_token_flow(
    build_auth, session_storage: MemorySessionStorage
):
    lookups: list[str] = []
    issued: list[TokenIssueRequest] = []

    def get_client(client_id: str) -> OAuthClient | None:
        lookups.append(client_id)
        return APP_CLIENT if client_id == APP_CLIENT.client_id else None

    def issue_token(request: TokenIssueRequest) -> tuple[str, int]:
        issued.append(request)
        return "app-token", 900

    mock_token_and_userinfo(email="test@example.com", provider_user_id="token-flow")
    auth = build_auth(
        config={
            "account_linking": {"enabled": True},
            "session": {"cookies": {"auth": True}},
        },
        oauth_server=OAuthServer(get_client=get_client, token_issuer=issue_token),
    )
    with _client(auth) as browser:
        state = _start_oauth_server_flow(browser, "token")
        response = browser.get(
            "/fake/callback", params={"code": "provider-code", "state": state}
        )
        assert response.status_code == 302, response.text
        location = urlparse(response.headers["location"])
        assert (
            f"{location.scheme}://{location.netloc}{location.path}"
            == (CLIENT_PARAMS["redirect_uri"])
        )
        code = parse_qs(location.query)["code"][0]
        response = browser.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": CLIENT_PARAMS["client_id"],
                "code": code,
                "redirect_uri": CLIENT_PARAMS["redirect_uri"],
                "code_verifier": VERIFIER,
            },
        )

    assert response.status_code == 200, response.text
    assert response.json()["access_token"] == "app-token"
    assert [request.grant_type for request in issued] == ["authorization_code"]
    assert issued[0].client_id == "app-client"
    assert lookups and set(lookups) == {"app-client"}
    # The application's token_issuer minted the credential, not session storage.
    assert not session_storage.records


def test_openapi_without_oauth_server_is_self_contained(
    secondary_storage, accounts_storage, session_storage, providers
):
    auth = CrossAuth(
        providers=providers,
        storage=secondary_storage,
        accounts_storage=accounts_storage,
        session_storage=session_storage,
        config={"session": {"cookies": {"auth": True}}},
    )
    # A plain app: no fixture merges auth.router.extra_schemas into the schema.
    app = FastAPI()
    app.include_router(auth.router)

    schema = app.openapi()

    assert _missing_refs(schema) == set()
    assert "/token" not in schema["paths"]
    assert not any(
        path.endswith(("/authorize", "/link", "/finalize-link"))
        for path in schema["paths"]
    )
    assert auth.router.extra_schemas == {}


def _client(auth: CrossAuth) -> TestClient:
    app = FastAPI()
    app.include_router(auth.router)
    return TestClient(app, follow_redirects=False)


def _start_oauth_server_flow(
    client: TestClient, flow: str, *, provider_id: str = "fake"
) -> str:
    if flow == "token":
        _, state = start_provider_auth(
            client, f"/{provider_id}/authorize", CLIENT_PARAMS
        )
        return state

    response = client.post(
        f"/{provider_id}/link",
        json={
            "client_id": CLIENT_PARAMS["client_id"],
            "redirect_uri": CLIENT_PARAMS["redirect_uri"],
            "code_challenge": CLIENT_PARAMS["code_challenge"],
            "code_challenge_method": "S256",
        },
        headers={"Authorization": "Bearer test"},
    )
    assert response.status_code == 200, response.text
    authorization_url = response.json()["authorization_url"]
    return parse_qs(urlparse(authorization_url).query)["state"][0]


def _codes(storage: MemoryStorage) -> list[str]:
    return [
        key
        for key in storage.data
        if key.startswith(("oauth:code:", "oauth:link_request:"))
    ]


@pytest.mark.parametrize("method", ["GET", "POST"])
@pytest.mark.parametrize("flow", ["token", "link"])
@respx.mock
def test_pending_oauth_server_callback_is_refused_after_disabling(
    build_auth,
    secondary_storage: MemoryStorage,
    accounts_storage: MemoryAccountsStorage,
    session_storage: MemorySessionStorage,
    flow: str,
    method: str,
):
    mock_token_and_userinfo(email="pending@example.com", provider_user_id="pending")
    config: Config = {
        "account_linking": {"enabled": True},
        "session": {"cookies": {"auth": True}},
    }
    with _client(build_auth(config=config)) as before:
        state = _start_oauth_server_flow(before, flow)
        cookies = dict(before.cookies)
    users_before = set(accounts_storage.data)

    disabled = build_auth(config=config, oauth_server=None)
    seen: list[str] = []
    for event in ("token.authorization_code", "user.create", "social_account.create"):
        disabled._context.hooks.register_after(
            event, lambda _event, name=event: seen.append(name)
        )

    with _client(disabled) as browser:
        browser.cookies.update(cookies)
        params = {"code": "provider-code", "state": state}
        if method == "POST":
            response = browser.post("/fake/callback", params=params)
            assert response.status_code == 303
            response = browser.get(response.headers["location"])
        else:
            response = browser.get("/fake/callback", params=params)

    assert response.status_code == 400
    assert response.json() == {
        "error": "invalid_request",
        "error_description": "The OAuth server is disabled",
    }
    assert "location" not in response.headers
    # The bound browser consumed the attempt and its binding cookie is cleared.
    assert secondary_storage.get(f"oauth:authorization_request:v2:{state}") is None
    assert f"cross_auth_oauth_{state}=" in response.headers["set-cookie"]
    assert "Max-Age=0" in response.headers["set-cookie"]
    # Nothing was exchanged, created, linked, issued or announced.
    assert not respx.calls
    assert set(accounts_storage.data) == users_before
    assert accounts_storage.data["test"].social_accounts == []
    assert _codes(secondary_storage) == []
    assert not session_storage.records
    assert seen == []


@respx.mock
def test_unbound_browser_cannot_consume_a_pending_oauth_server_callback(
    build_auth, secondary_storage
):
    with _client(build_auth()) as victim:
        state = _start_oauth_server_flow(victim, "token")

    with _client(build_auth(oauth_server=None)) as attacker:
        response = attacker.get(
            "/fake/callback", params={"code": "provider-code", "state": state}
        )

    assert response.status_code == 400
    assert response.json()["error_description"] == (
        "OAuth callback belongs to another browser"
    )
    assert secondary_storage.get(f"oauth:authorization_request:v2:{state}") is not None
    assert not respx.calls


@respx.mock
def test_pending_session_flow_survives_disabling(build_auth):
    mock_token_and_userinfo(email="survivor@example.com", provider_user_id="kept")
    with _client(build_auth()) as before:
        _, login_state = start_provider_auth(before, "/fake/login")
        cookies = dict(before.cookies)

    with _client(build_auth(oauth_server=None)) as browser:
        browser.cookies.update(cookies)
        response = browser.get(
            "/fake/callback", params={"code": "code", "state": login_state}
        )

    assert response.status_code == 302
    assert response.cookies.get("session_id")


@respx.mock
def test_session_login_and_connect_without_oauth_server(
    build_auth, accounts_storage: MemoryAccountsStorage
):
    mock_token_and_userinfo(email="social@example.com", provider_user_id="social-1")
    with _client(build_auth(oauth_server=None)) as browser:
        _, state = start_provider_auth(browser, "/fake/login")
        response = browser.get(
            "/fake/callback", params={"code": "code", "state": state}
        )
        assert response.status_code == 302
        assert response.cookies.get("session_id")

    mock_token_and_userinfo(email="test@example.com", provider_user_id="connected")
    with _client(build_auth(oauth_server=None)) as browser:
        response = browser.get(
            "/fake/connect", headers={"Authorization": "Bearer test"}
        )
        state = parse_qs(urlparse(response.headers["location"]).query)["state"][0]
        response = browser.get(
            "/fake/callback",
            params={"code": "code", "state": state},
            headers={"Authorization": "Bearer test"},
        )

    assert response.status_code == 302
    connected = accounts_storage.find_social_account(
        provider="fake", provider_user_id="connected"
    )
    assert connected is not None
    assert connected.user_id == "test"
    assert connected.is_login_method is False


@pytest.fixture
def social_only(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: MemorySessionStorage,
) -> CrossAuth:
    return CrossAuth(
        providers=[GoogleProvider(client_id=CLIENT_ID, client_secret="secret")],
        storage=secondary_storage,
        accounts_storage=accounts_storage,
        session_storage=session_storage,
        config={"session": {"cookies": {"auth": True, "secure": False}}},
    )


@pytest.fixture
def social_only_client(social_only: CrossAuth):
    app = FastAPI()
    app.include_router(social_only.router, prefix="/auth")

    @app.get("/me")
    def me(user: Annotated[User | None, Depends(social_only.get_current_user)]):
        return {"id": None if user is None else str(user.id)}

    with TestClient(app, follow_redirects=False) as client:
        yield client


def test_google_cookie_sign_in_without_oauth_server(
    social_only_client: TestClient, accounts_storage: MemoryAccountsStorage
):
    with respx.mock(assert_all_called=False) as router:
        google = FakeGoogle(router)
        google.install()
        response = social_only_client.get("/auth/google/login")
        assert response.status_code == 302
        location = response.headers["location"]
        authorization = Authorization(
            url=location,
            params={
                key: values[0]
                for key, values in parse_qs(urlparse(location).query).items()
            },
        )
        code = google.approve(authorization, Account(email="social@gmail.com"))
        response = social_only_client.get(
            "/auth/google/callback", params={"state": authorization.state, "code": code}
        )

    assert response.status_code == 302
    assert response.headers["location"] == "/"
    user = accounts_storage.find_user_by_email("social@gmail.com")
    assert user is not None
    assert social_only_client.get("/me").json() == {"id": str(user.id)}


def test_password_and_bearer_sessions_without_oauth_server(
    social_only: CrossAuth, social_only_client: TestClient
):
    user = social_only.authenticate("test@example.com", TEST_PASSWORD)
    assert user is not None
    assert social_only.authenticate("test@example.com", "wrong") is None

    token, record = social_only.issue_session_token(str(user.id))
    headers = {"Authorization": f"Bearer {token}"}
    assert social_only_client.get("/me", headers=headers).json() == {"id": "test"}

    social_only.revoke_session(record.id, user_id=user.id)
    assert social_only_client.get("/me", headers=headers).json() == {"id": None}


@pytest.fixture
def apple_provider() -> AppleProvider:
    key = ec.generate_private_key(ec.SECP256R1())
    return AppleProvider(
        client_id="com.example.web",
        team_id="TEAM123456",
        key_id="KEY1234567",
        private_key=key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode(),
    )


@pytest.mark.parametrize("flow", ["token", "link"])
@pytest.mark.parametrize("provider_error", [False, True])
@respx.mock
def test_disabled_oauth_server_rejects_apple_form_post(
    build_auth,
    apple_provider: AppleProvider,
    secondary_storage: MemoryStorage,
    accounts_storage: MemoryAccountsStorage,
    session_storage: MemorySessionStorage,
    flow: str,
    provider_error: bool,
):
    config: Config = {
        "account_linking": {"enabled": True},
        "session": {"cookies": {"auth": True}},
    }
    with _client(build_auth(providers=[apple_provider], config=config)) as before:
        state = _start_oauth_server_flow(before, flow, provider_id="apple")
        cookies = dict(before.cookies)
    users_before = set(accounts_storage.data)

    with _client(
        build_auth(providers=[apple_provider], config=config, oauth_server=None)
    ) as browser:
        browser.cookies.update(cookies)
        form = {"state": state}
        form.update(
            {"error": "access_denied"} if provider_error else {"code": "unused-code"}
        )
        # Apple's callback fields are form data, not query parameters.
        response = browser.post("/apple/callback", data=form)
        assert response.status_code == 303
        location = response.headers["location"]
        resume = parse_qs(urlparse(location).query)["resume"][0]
        assert "unused-code" not in location
        response = browser.get(location)

    assert response.status_code == 400
    assert response.json()["error_description"] == "The OAuth server is disabled"
    assert "location" not in response.headers
    assert secondary_storage.get(f"oauth:authorization_request:v2:{state}") is None
    assert secondary_storage.get(f"oauth:form_post:{resume}") is None
    assert "Max-Age=0" in response.headers["set-cookie"]
    assert not respx.calls
    assert set(accounts_storage.data) == users_before
    assert accounts_storage.data["test"].social_accounts == []
    assert _codes(secondary_storage) == []
    assert not session_storage.records


@pytest.mark.parametrize("flow", ["token", "link"])
@respx.mock
def test_unbound_browser_cannot_consume_apple_form_post(
    build_auth,
    apple_provider: AppleProvider,
    secondary_storage: MemoryStorage,
    flow: str,
):
    config: Config = {
        "account_linking": {"enabled": True},
        "session": {"cookies": {"auth": True}},
    }
    with _client(build_auth(providers=[apple_provider], config=config)) as before:
        state = _start_oauth_server_flow(before, flow, provider_id="apple")
        cookies = dict(before.cookies)

    disabled = build_auth(providers=[apple_provider], config=config, oauth_server=None)
    with _client(disabled) as browser:
        browser.cookies.update(cookies)
        response = browser.post(
            "/apple/callback", data={"state": state, "code": "unused-code"}
        )
        assert response.status_code == 303
        location = response.headers["location"]
        resume = parse_qs(urlparse(location).query)["resume"][0]
        authorization_key = f"oauth:authorization_request:v2:{state}"
        continuation_key = f"oauth:form_post:{resume}"
        authorization = secondary_storage.get(authorization_key)
        continuation = secondary_storage.get(continuation_key)
        assert authorization is not None
        assert continuation is not None

        with _client(disabled) as attacker:
            response = attacker.get(location)
        assert response.status_code == 400
        assert response.json()["error_description"] == (
            "OAuth callback belongs to another browser"
        )
        assert secondary_storage.get(authorization_key) == authorization
        assert secondary_storage.get(continuation_key) == continuation

        # The bound browser can still resume, then consume the refused attempt.
        response = browser.get(location)
        assert response.json()["error_description"] == "The OAuth server is disabled"
        assert secondary_storage.get(authorization_key) is None
        assert secondary_storage.get(continuation_key) is None
    assert not respx.calls
