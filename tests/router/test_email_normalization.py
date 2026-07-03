import respx
from fastapi import FastAPI
from fastapi.testclient import TestClient

from cross_auth._storage import AccountsStorage

from .conftest import mock_token_and_userinfo, start_provider_auth


@respx.mock
def test_signup_stores_normalized_email(
    client: TestClient,
    accounts_storage: AccountsStorage,
):
    mock_token_and_userinfo(email="  Alice@Example.COM ")
    _, state = start_provider_auth(client, "/fake/login")

    resp = client.get(
        "/fake/callback", params={"code": "provider-code", "state": state}
    )

    assert resp.status_code == 302
    assert accounts_storage.find_user_by_email("alice@example.com") is not None


@respx.mock
def test_mixed_case_provider_email_matches_existing_account(client: TestClient):
    # The seeded user is test@example.com. Without account linking enabled the
    # callback must recognize the differently-cased provider email as the same
    # existing account (and refuse to create a duplicate), which proves the
    # lookup is normalized.
    mock_token_and_userinfo(email="Test@Example.COM")
    _, state = start_provider_auth(client, "/fake/login")

    resp = client.get(
        "/fake/callback", params={"code": "provider-code", "state": state}
    )

    assert resp.status_code == 400
    assert resp.json()["error"] == "account_not_linked"


@respx.mock
def test_custom_normalizer_is_applied(build_auth, accounts_storage):
    def collapse_gmail_dots(email: str) -> str:
        email = email.strip().lower()
        local, _, domain = email.partition("@")
        if domain == "gmail.com":
            local = local.replace(".", "")
        return f"{local}@{domain}"

    auth = build_auth(normalize_email=collapse_gmail_dots)
    app = FastAPI()
    app.include_router(auth.router)

    with TestClient(app, follow_redirects=False) as client:
        mock_token_and_userinfo(email="P.a.trick@Gmail.com")
        _, state = start_provider_auth(client, "/fake/login")

        resp = client.get(
            "/fake/callback", params={"code": "provider-code", "state": state}
        )

    assert resp.status_code == 302
    assert accounts_storage.find_user_by_email("patrick@gmail.com") is not None
