"""Link redemption validates the client before consuming its single-use code."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from threading import Barrier, Lock

import pytest
import respx
import time_machine

from .conftest import mock_token_and_userinfo
from .test_link_flow import _auth_enabled_client, _store_link_code, _LINK_CODE_VERIFIER

NOW = datetime(2026, 9, 17, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    "body",
    [
        None,
        [],
        "text",
        42,
        {"link_code": ["link-code"]},
        {"link_code": "link-code", "code_verifier": ["test"]},
        {"link_code": "link-code", "code_verifier": 123},
        {"link_code": "link-code", "code_verifier": "é"},
        {"link_code": "link-code", "code_verifier": "\\ud800"},
    ],
)
@respx.mock
def test_malformed_redemption_does_not_consume_link_code(
    build_auth, secondary_storage, body
):
    import json

    code = _store_link_code(secondary_storage)
    with _auth_enabled_client(build_auth) as client:
        response = client.post(
            "/fake/finalize-link",
            headers={
                "Authorization": "Bearer test",
                "Content-Type": "application/json",
            },
            content=json.dumps(body),
        )

    assert response.status_code == 400
    assert secondary_storage.get(f"oauth:link_request:v2:{code}") is not None
    assert not respx.calls


@time_machine.travel(NOW, tick=False)
@respx.mock
def test_link_code_is_expired_at_exact_deadline(build_auth, secondary_storage):
    code = _store_link_code(secondary_storage, expires_at=NOW)

    with _auth_enabled_client(build_auth) as client:
        response = client.post(
            "/fake/finalize-link",
            headers={"Authorization": "Bearer test"},
            json={"link_code": code, "code_verifier": _LINK_CODE_VERIFIER},
        )

    assert response.status_code == 400
    assert response.json()["error_description"] == "Link code has expired"
    assert not respx.calls


@respx.mock
def test_code_expiring_during_redemption_never_reaches_provider(
    build_auth, secondary_storage, fake_provider, monkeypatch
):
    with time_machine.travel(NOW, tick=False) as clock:
        code = _store_link_code(
            secondary_storage, expires_at=NOW + timedelta(seconds=1)
        )
        monkeypatch.setattr(
            fake_provider,
            "validate_link_data",
            lambda data: clock.shift(timedelta(seconds=2)),
        )

        with _auth_enabled_client(build_auth) as client:
            response = client.post(
                "/fake/finalize-link",
                headers={"Authorization": "Bearer test"},
                json={"link_code": code, "code_verifier": _LINK_CODE_VERIFIER},
            )

    assert response.status_code == 400
    assert response.json()["error_description"] == "Link code has expired"
    assert secondary_storage.get(f"oauth:link_request:v2:{code}") is None
    assert not respx.calls


@respx.mock
def test_invalid_user_and_verifier_leave_code_redeemable(
    build_auth, secondary_storage, accounts_storage
):
    code = _store_link_code(secondary_storage)
    accounts_storage.create_user(
        user_info={"id": "other"}, email="other@example.com", email_verified=True
    )
    mock_token_and_userinfo(email="test@example.com")

    with _auth_enabled_client(build_auth) as client:
        for user, verifier, expected in [
            ("other", _LINK_CODE_VERIFIER, 403),
            ("test", "wrong", 400),
            ("test", _LINK_CODE_VERIFIER, 200),
            ("test", _LINK_CODE_VERIFIER, 400),
        ]:
            response = client.post(
                "/fake/finalize-link",
                headers={"Authorization": f"Bearer {user}"},
                json={"link_code": code, "code_verifier": verifier},
            )
            assert response.status_code == expected

    assert len(respx.calls) == 2
    assert len(accounts_storage.data["test"].social_accounts) == 1
    assert accounts_storage.data["other"].social_accounts == []


@respx.mock
def test_concurrent_redemptions_exchange_provider_code_once(
    build_auth, secondary_storage, accounts_storage, monkeypatch
):
    code = _store_link_code(secondary_storage)
    barrier = Barrier(2)
    lock = Lock()
    original_pop = secondary_storage.pop

    def atomic_pop(key):
        barrier.wait(timeout=5)
        with lock:
            return original_pop(key)

    monkeypatch.setattr(secondary_storage, "pop", atomic_pop)
    mock_token_and_userinfo(email="test@example.com")

    def redeem():
        with _auth_enabled_client(build_auth) as client:
            return client.post(
                "/fake/finalize-link",
                headers={"Authorization": "Bearer test"},
                json={"link_code": code, "code_verifier": _LINK_CODE_VERIFIER},
            )

    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = list(executor.map(lambda _: redeem(), range(2)))

    assert sorted(response.status_code for response in responses) == [200, 400]
    assert len(respx.calls) == 2
    assert len(accounts_storage.data["test"].social_accounts) == 1


@pytest.mark.parametrize(
    ("registry", "expected_error"),
    [
        ({}, "invalid_client"),
        ({"app-client": ["http://client.example/replacement"]}, "invalid_redirect_uri"),
    ],
)
@respx.mock
def test_finalization_rechecks_current_client_registration(
    build_auth, secondary_storage, registry, expected_error
):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    code = _store_link_code(secondary_storage)
    auth = build_auth(
        config={
            "account_linking": {"enabled": True},
            "client_redirect_uris": registry,
        }
    )
    app = FastAPI()
    app.include_router(auth.router)

    with TestClient(app) as client:
        response = client.post(
            "/fake/finalize-link",
            headers={"Authorization": "Bearer test"},
            json={"link_code": code, "code_verifier": _LINK_CODE_VERIFIER},
        )

    assert response.status_code == 400
    assert response.json()["error"] == expected_error
    assert secondary_storage.get(f"oauth:link_request:v2:{code}") is not None
    assert not respx.calls


@respx.mock
def test_non_utf8_json_is_rejected_without_consuming_link_code(
    context, fake_provider, secondary_storage
):
    import json

    from cross_web import HTTPRequest, TestingHTTPRequestAdapter

    from cross_auth._auth_flow import finalize_link

    code = _store_link_code(secondary_storage)
    request = HTTPRequest(
        TestingHTTPRequestAdapter(
            headers={"Authorization": "Bearer test"}, body=b"\xff"
        )
    )

    response = finalize_link(fake_provider, request, context)

    assert response.status_code == 400
    assert response.body is not None
    assert json.loads(response.body)["error"] == "invalid_request"
    assert secondary_storage.get(f"oauth:link_request:v2:{code}") is not None
    assert not respx.calls
