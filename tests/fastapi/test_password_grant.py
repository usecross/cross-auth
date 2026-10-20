"""The deprecated OAuth password grant: off by default, accepted with a warning
under ``OAuthServer(password_grant=True)``. Schemas are read from plain FastAPI
apps, without merging ``router.extra_schemas``."""

import json
import re
import warnings
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from cross_auth import OAuthServer
from cross_auth._storage import AccountsStorage, SecondaryStorage
from cross_auth.fastapi import CrossAuth
from cross_auth.router import AuthRouter

from ..conftest import (
    TEST_CLIENTS,
    TEST_PASSWORD,
    MemoryAccountsStorage,
    MemorySessionStorage,
)

PASSWORD_GRANT = {
    "grant_type": "password",
    "client_id": "test",
    "username": "test@example.com",
    "password": TEST_PASSWORD,
}
CODE_GRANT = {
    "grant_type": "authorization_code",
    "client_id": "test",
    "redirect_uri": "http://valid-frontend.com/callback",
    "code_verifier": "test",
}
DEPRECATION = "The OAuth password grant is deprecated"


def _server(*, password_grant: bool) -> OAuthServer:
    return OAuthServer(get_client=TEST_CLIENTS.get, password_grant=password_grant)


def _auth(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: MemorySessionStorage,
    oauth_server: OAuthServer,
) -> CrossAuth:
    return CrossAuth(
        providers=[],
        storage=secondary_storage,
        accounts_storage=accounts_storage,
        session_storage=session_storage,
        oauth_server=oauth_server,
    )


def _app(router: AuthRouter) -> FastAPI:
    app = FastAPI()
    app.include_router(router)
    return app


@pytest.fixture
def build(secondary_storage, accounts_storage, session_storage):
    def make(oauth_server: OAuthServer) -> TestClient:
        auth = _auth(secondary_storage, accounts_storage, session_storage, oauth_server)
        return TestClient(_app(auth.router))

    return make


@pytest.fixture
def hook_calls(monkeypatch) -> Iterator[list[str]]:
    """Record account lookups; tests add the hooks they expect not to run."""
    calls: list[str] = []
    original = MemoryAccountsStorage.find_user_by_email

    def find_user_by_email(self, email: str):
        calls.append("find_user_by_email")
        return original(self, email)

    monkeypatch.setattr(MemoryAccountsStorage, "find_user_by_email", find_user_by_email)
    yield calls


def test_oauth_server_refuses_the_password_grant_by_default():
    assert OAuthServer().password_grant is False


@pytest.mark.parametrize(
    "data",
    [
        PASSWORD_GRANT,
        # Refused before validation: legacy fields are not required to be sent.
        {"grant_type": "password"},
    ],
)
@pytest.mark.parametrize(
    "oauth_server",
    [OAuthServer(get_client=TEST_CLIENTS.get), _server(password_grant=False)],
    ids=["default", "explicit"],
)
def test_disabled_password_grant_is_unsupported_without_side_effects(
    secondary_storage,
    accounts_storage,
    session_storage: MemorySessionStorage,
    hook_calls: list[str],
    data: dict[str, str],
    oauth_server: OAuthServer,
):
    auth = _auth(secondary_storage, accounts_storage, session_storage, oauth_server)
    for event in ("token.password", "authenticate", "login"):
        auth._context.hooks.register_before(
            event, lambda _event, name=event: hook_calls.append(name)
        )

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        response = TestClient(_app(auth.router)).post("/token", data=data)

    assert response.status_code == 400
    assert response.json() == {
        "error": "unsupported_grant_type",
        "error_description": "Grant type 'password' is not supported",
    }
    assert hook_calls == []
    assert not session_storage.records
    assert caught == []


def test_disabled_password_grant_keeps_the_code_grant(build, valid_code: str):
    client = build(_server(password_grant=False))

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        response = client.post("/token", data={**CODE_GRANT, "code": valid_code})

    assert response.status_code == 200
    assert response.json()["token_type"] == "Bearer"
    assert caught == []


def test_password_grant_use_warns_once(build, session_storage: MemorySessionStorage):
    client = build(_server(password_grant=True))

    with pytest.warns(DeprecationWarning, match=DEPRECATION) as caught:
        response = client.post("/token", data=PASSWORD_GRANT)

    assert response.status_code == 200
    assert len(caught) == 1
    message = str(caught[0].message)
    assert "1.0" in message
    assert "OAuthServer(password_grant=True)" in message
    for secret in (TEST_PASSWORD, "test@example.com", response.json()["access_token"]):
        assert secret not in message
    assert len(session_storage.records) == 1


def test_failed_password_grant_still_warns(build):
    client = build(_server(password_grant=True))

    with pytest.warns(DeprecationWarning, match=DEPRECATION):
        response = client.post(
            "/token", data={**PASSWORD_GRANT, "password": "wrong-password"}
        )

    assert response.json()["error"] == "invalid_grant"


@pytest.mark.parametrize("password_grant", [False, True])
def test_startup_and_code_grant_do_not_warn(
    secondary_storage,
    accounts_storage,
    session_storage,
    valid_code: str,
    password_grant: bool,
):
    oauth_server = _server(password_grant=password_grant)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        auth = _auth(secondary_storage, accounts_storage, session_storage, oauth_server)
        app = _app(auth.router)
        app.openapi()
        response = TestClient(app).post(
            "/token", data={**CODE_GRANT, "code": valid_code}
        )

    assert response.status_code == 200
    assert caught == []


def _missing_refs(schema: dict[str, Any]) -> set[str]:
    refs = set(re.findall(r'"#/components/schemas/([^"]+)"', json.dumps(schema)))
    return refs - set(schema.get("components", {}).get("schemas", {}))


def _token_body(schema: dict[str, Any]) -> dict[str, Any]:
    operation = schema["paths"]["/token"]["post"]
    assert "deprecated" not in operation
    return operation["requestBody"]["content"]["application/x-www-form-urlencoded"][
        "schema"
    ]


def _grant_type(variant: dict[str, Any]) -> str:
    return variant["properties"]["grant_type"]["const"]


def _router(
    secondary_storage,
    accounts_storage,
    session_storage,
    oauth_server: OAuthServer,
    *,
    use_router: bool,
) -> AuthRouter:
    if use_router:
        return AuthRouter(
            [],
            secondary_storage,
            accounts_storage,
            lambda request: None,
            oauth_server=oauth_server,
        )
    return _auth(
        secondary_storage, accounts_storage, session_storage, oauth_server
    ).router


@pytest.mark.parametrize("use_router", [False, True])
def test_legacy_schema_marks_only_the_password_variant_deprecated(
    secondary_storage, accounts_storage, session_storage, use_router: bool
):
    router = _router(
        secondary_storage,
        accounts_storage,
        session_storage,
        _server(password_grant=True),
        use_router=use_router,
    )

    schema = _app(router).openapi()
    body = _token_body(schema)

    assert _missing_refs(schema) == set()
    assert {
        _grant_type(variant): variant.get("deprecated") for variant in body["oneOf"]
    } == {"authorization_code": None, "password": True}
    assert router.extra_schemas["PasswordGrantRequest"]["deprecated"] is True
    assert "deprecated" not in router.extra_schemas["AuthorizationCodeGrantRequest"]


@pytest.mark.parametrize("use_router", [False, True])
def test_default_schema_has_only_the_code_grant(
    secondary_storage, accounts_storage, session_storage, use_router: bool
):
    router = _router(
        secondary_storage,
        accounts_storage,
        session_storage,
        OAuthServer(),
        use_router=use_router,
    )

    schema = _app(router).openapi()
    body = _token_body(schema)

    assert _missing_refs(schema) == set()
    assert _grant_type(body) == "authorization_code"
    assert "password" not in json.dumps(schema["paths"]["/token"])
    assert "PasswordGrantRequest" not in router.extra_schemas
    assert "PasswordGrantRequest" not in schema.get("components", {}).get("schemas", {})


def test_password_grant_is_not_a_constructor_argument(
    secondary_storage, accounts_storage
):
    removed: dict[str, Any] = {"password_grant": True}

    with pytest.raises(TypeError, match="password_grant"):
        CrossAuth(
            providers=[],
            storage=secondary_storage,
            accounts_storage=accounts_storage,
            **removed,
        )
    with pytest.raises(TypeError, match="password_grant"):
        AuthRouter(
            providers=[],
            secondary_storage=secondary_storage,
            accounts_storage=accounts_storage,
            get_user_from_request=lambda request: None,
            **removed,
        )
