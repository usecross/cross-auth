"""Malformed provider callbacks answer an OAuth error, not a server error."""

from fastapi import FastAPI
from fastapi.testclient import TestClient

from cross_auth.social_providers.apple import AppleProvider

from ..conftest import MemoryAccountsStorage, MemorySessionStorage, MemoryStorage
from .conftest import _build_auth


def test_apple_callback_by_get_is_a_client_error(
    secondary_storage: MemoryStorage,
    accounts_storage: MemoryAccountsStorage,
    session_storage: MemorySessionStorage,
):
    # Apple posts its callback (response_mode=form_post); a GET with the same
    # parameters, which anyone can send, is refused like any bad request.
    apple = AppleProvider(
        "com.example.app", team_id="team", key_id="key", private_key="unused"
    )
    auth = _build_auth(
        storage=secondary_storage,
        accounts_storage=accounts_storage,
        session_storage=session_storage,
        providers=[apple],
    )
    app = FastAPI()
    app.include_router(auth.router)

    with TestClient(app, follow_redirects=False) as client:
        response = client.get(
            "/apple/callback", params={"code": "code", "state": "state"}
        )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"
