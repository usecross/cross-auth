"""The OAuth 2.0 Device Authorization Grant (RFC 8628).

A device asks ``POST /device/code`` for a device code and a user code, the
signed-in user approves the request in a browser, and the device polls
``/token`` until the poll that finds the approval gets the token. The device
and the browser are separate clients here, each with its own address and user
agent, as they are separate machines in use.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
import time_machine
from fastapi import FastAPI
from fastapi.testclient import TestClient

from cross_auth import (
    DeviceAuthorization,
    DeviceGrant,
    OAuthClient,
    OAuthServer,
    TokenIssueRequest,
)
from cross_auth._device import format_user_code, normalize_user_code
from cross_auth._session import create_session
from cross_auth.exceptions import CrossAuthException
from cross_auth.fastapi import CrossAuth
from cross_auth.hooks import (
    AfterDeviceApproveEvent,
    AfterDeviceCodeEvent,
    AfterLoginEvent,
    AfterTokenDeviceCodeEvent,
    BeforeDeviceApproveEvent,
    BeforeDeviceCodeEvent,
    BeforeLoginEvent,
    BeforeTokenDeviceCodeEvent,
)

from ..conftest import (
    MemoryAccountsStorage,
    MemorySessionRecord,
    MemorySessionStorage,
    MemoryStorage,
)
from ..conftest import User as MemoryUser

NOW = datetime(2026, 11, 25, 12, 0, tzinfo=UTC)
GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"
VERIFICATION_URI = "https://example.com/device"
DEVICE_IP = "203.0.113.7"
DEVICE_USER_AGENT = "example-cli/1.4 (darwin; arm64)"
BROWSER_IP = "198.51.100.4"
BROWSER_USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_1)"
USER_CODE = re.compile(r"[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}")

CLIENTS = {
    "cli": OAuthClient(client_id="cli", redirect_uris=(), client_name="Example CLI"),
    "other-cli": OAuthClient(client_id="other-cli", redirect_uris=()),
}


class InterleavingStorage(MemoryStorage):
    """A memory storage that can run a competing request in the middle of a pop.

    Requests here run one after another, so a race is staged: a callback
    registered for a key prefix runs once, before or after the next pop of a
    matching key.
    """

    def __init__(self) -> None:
        super().__init__()
        self.before_pop: dict[str, Callable[[], None]] = {}
        self.after_pop: dict[str, Callable[[], None]] = {}
        # The TTL of each key's last write: the memory storage expires keys on
        # the monotonic clock, which time_machine does not move.
        self.ttls: dict[str, int | None] = {}

    def set(self, key: str, value: str, ttl: int | None = None) -> None:
        self.ttls[key] = ttl
        super().set(key, value, ttl)

    def pop(self, key: str) -> str | None:
        self._run(self.before_pop, key)
        value = super().pop(key)
        self._run(self.after_pop, key)
        return value

    @staticmethod
    def _run(callbacks: dict[str, Callable[[], None]], key: str) -> None:
        for prefix in [prefix for prefix in callbacks if key.startswith(prefix)]:
            callbacks.pop(prefix)()

    def device_entries(self) -> dict[str, str]:
        return {
            key: value
            for key, (value, _) in self.data.items()
            if key.startswith("oauth:device:")
        }


@pytest.fixture(autouse=True)
def clock() -> Iterator[time_machine.Traveller]:
    with time_machine.travel(NOW, tick=False) as traveller:
        yield traveller


@pytest.fixture
def secondary_storage() -> InterleavingStorage:
    return InterleavingStorage()


@pytest.fixture
def other_user(accounts_storage: MemoryAccountsStorage) -> MemoryUser:
    user = MemoryUser(
        id="other",
        email="other@example.com",
        email_verified=True,
        hashed_password=None,
        social_accounts=[],
    )
    accounts_storage.data["other"] = user
    return user


def make_auth(
    secondary_storage: MemoryStorage,
    accounts_storage: MemoryAccountsStorage,
    session_storage: MemorySessionStorage | None,
    *,
    device: DeviceGrant | None = None,
    get_client: Callable[[str], OAuthClient | None] | None = CLIENTS.get,
    **kwargs: Any,
) -> CrossAuth:
    server_options = kwargs.pop("oauth_server_options", {})
    return CrossAuth(
        providers=[],
        storage=secondary_storage,
        accounts_storage=accounts_storage,
        session_storage=session_storage,
        oauth_server=OAuthServer(
            get_client=get_client,
            device=device or DeviceGrant(verification_uri=VERIFICATION_URI),
            **server_options,
        ),
        **kwargs,
    )


@pytest.fixture
def auth(
    secondary_storage: InterleavingStorage,
    accounts_storage: MemoryAccountsStorage,
    session_storage: MemorySessionStorage,
) -> CrossAuth:
    return make_auth(secondary_storage, accounts_storage, session_storage)


def make_app(auth: CrossAuth) -> FastAPI:
    app = FastAPI()
    app.include_router(auth.router)
    return app


@pytest.fixture
def device(auth: CrossAuth) -> TestClient:
    """The CLI: its own address and user agent, and no cookies."""
    return TestClient(
        make_app(auth),
        client=(DEVICE_IP, 50000),
        headers={"User-Agent": DEVICE_USER_AGENT},
    )


@pytest.fixture
def browser(auth: CrossAuth) -> TestClient:
    """Where the user approves, signed in on another machine."""
    return TestClient(
        make_app(auth),
        client=(BROWSER_IP, 50000),
        headers={"User-Agent": BROWSER_USER_AGENT},
    )


def start(device: TestClient, *, client_id: str = "cli", **form: str) -> dict[str, Any]:
    response = device.post("/device/code", data={"client_id": client_id, **form})
    assert response.status_code == 200, response.text
    return response.json()


def poll(
    device: TestClient, device_code: str, *, client_id: str = "cli"
) -> httpx.Response:
    return device.post(
        "/token",
        data={
            "grant_type": GRANT_TYPE,
            "client_id": client_id,
            "device_code": device_code,
        },
    )


def error_of(response: httpx.Response) -> str:
    assert response.status_code == 400, response.text
    return response.json()["error"]


def sign_in(session_storage: MemorySessionStorage, user_id: str = "test") -> str:
    """Sign the browser's user in without the login hooks the tests observe."""
    token, _ = create_session(user_id, session_storage)
    return token


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def approve(browser: TestClient, token: str, user_code: str) -> httpx.Response:
    return browser.post(
        "/device/approve", json={"user_code": user_code}, headers=bearer(token)
    )


def deny(browser: TestClient, token: str, user_code: str) -> httpx.Response:
    return browser.post(
        "/device/deny", json={"user_code": user_code}, headers=bearer(token)
    )


def lookup(browser: TestClient, token: str, user_code: str) -> httpx.Response:
    return browser.get(
        "/device", params={"user_code": user_code}, headers=bearer(token)
    )


def device_sessions(session_storage: MemorySessionStorage) -> list[MemorySessionRecord]:
    return [
        record
        for record in session_storage.records.values()
        if record.login_method == "device"
    ]


def wait(clock: time_machine.Traveller, seconds: int = 5) -> None:
    clock.shift(timedelta(seconds=seconds))


# Configuration


@pytest.mark.parametrize(
    "options",
    [
        {"verification_uri": "/device"},
        {"verification_uri": "example.com/device"},
        {"verification_uri": "ftp://example.com/device"},
        {"verification_uri": "https://example.com/device#code"},
        {"verification_uri": VERIFICATION_URI, "expires_in": 0},
        {"verification_uri": VERIFICATION_URI, "interval": -5},
        {"verification_uri": VERIFICATION_URI, "interval": True},
    ],
)
def test_device_grant_settings_are_validated(options: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="DeviceGrant"):
        DeviceGrant(**options)


def test_without_the_device_grant_nothing_is_mounted(
    secondary_storage, accounts_storage, session_storage
) -> None:
    auth = CrossAuth(
        providers=[],
        storage=secondary_storage,
        accounts_storage=accounts_storage,
        session_storage=session_storage,
        oauth_server=OAuthServer(get_client=CLIENTS.get),
    )
    client = TestClient(make_app(auth))

    assert client.post("/device/code", data={"client_id": "cli"}).status_code == 404
    assert client.get("/device", params={"user_code": "BCDF-GHJK"}).status_code == 404
    # Refused before validation, as the password grant is: no field is required.
    response = client.post(
        "/token", data={"grant_type": GRANT_TYPE, "client_id": "cli"}
    )
    assert response.json() == {
        "error": "unsupported_grant_type",
        "error_description": f"Grant type '{GRANT_TYPE}' is not supported",
    }
    paths = client.get("/openapi.json").json()["paths"]
    assert not [path for path in paths if path.startswith("/device")]
    with pytest.raises(RuntimeError, match="device grant is not enabled"):
        auth.get_device_authorization("BCDF-GHJK")
    assert secondary_storage.data == {}


def test_the_routes_and_grant_are_in_the_openapi_schema(device: TestClient) -> None:
    schema = device.get("/openapi.json").json()
    operations = {
        path: {method: operation["operationId"] for method, operation in item.items()}
        for path, item in schema["paths"].items()
        if path.startswith("/device")
    }

    assert operations == {
        "/device/code": {"post": "device_authorization"},
        "/device": {"get": "get_device_authorization"},
        "/device/approve": {"post": "approve_device_authorization"},
        "/device/deny": {"post": "deny_device_authorization"},
    }
    token_body = schema["paths"]["/token"]["post"]["requestBody"]["content"]
    grants = token_body["application/x-www-form-urlencoded"]["schema"]["oneOf"]
    assert [grant["title"] for grant in grants] == [
        "AuthorizationCodeGrantRequest",
        "DeviceCodeGrantRequest",
    ]


# The device authorization request


def test_the_device_gets_both_codes_and_where_to_enter_one(
    device: TestClient,
) -> None:
    response = device.post("/device/code", data={"client_id": "cli"})

    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    body = response.json()
    assert USER_CODE.fullmatch(body["user_code"])
    assert len(body["device_code"]) >= 43
    assert body == {
        "device_code": body["device_code"],
        "user_code": body["user_code"],
        "verification_uri": VERIFICATION_URI,
        "verification_uri_complete": (
            f"{VERIFICATION_URI}?user_code={body['user_code']}"
        ),
        "expires_in": 900,
        "interval": 5,
    }


def test_expiry_and_interval_can_be_configured(
    secondary_storage, accounts_storage, session_storage
) -> None:
    auth = make_auth(
        secondary_storage,
        accounts_storage,
        session_storage,
        device=DeviceGrant(
            verification_uri="https://example.com/activate?source=cli",
            expires_in=300,
            interval=10,
        ),
    )

    body = start(TestClient(make_app(auth)))

    assert body["expires_in"] == 300
    assert body["interval"] == 10
    assert body["verification_uri_complete"] == (
        f"https://example.com/activate?source=cli&user_code={body['user_code']}"
    )


@pytest.mark.parametrize(
    ("form", "error"),
    [
        ({}, "invalid_request"),
        ({"client_id": ""}, "invalid_request"),
        ({"client_id": "unknown"}, "invalid_client"),
    ],
)
def test_a_code_request_needs_a_registered_client(
    device: TestClient, secondary_storage, form: dict[str, str], error: str
) -> None:
    response = device.post("/device/code", data=form)

    assert error_of(response) == error
    assert secondary_storage.data == {}


def test_without_get_client_every_client_is_refused(
    secondary_storage, accounts_storage, session_storage
) -> None:
    auth = make_auth(
        secondary_storage, accounts_storage, session_storage, get_client=None
    )

    response = TestClient(make_app(auth)).post(
        "/device/code", data={"client_id": "cli"}
    )

    assert error_of(response) == "invalid_client"


# The approval page's lookup


def test_the_lookup_shows_who_asked_from_the_device(
    device: TestClient, browser: TestClient, session_storage
) -> None:
    codes = start(device, scope="deploy")
    token = sign_in(session_storage)

    response = lookup(browser, token, codes["user_code"])

    assert response.status_code == 200
    # The device's address and user agent, not the approving browser's.
    assert response.json() == {
        "client_id": "cli",
        "client_name": "Example CLI",
        "scope": "deploy",
        "ip": DEVICE_IP,
        "user_agent": DEVICE_USER_AGENT,
        "metadata": {},
        "created_at": "2026-11-25T12:00:00Z",
        "expires_at": "2026-11-25T12:15:00Z",
    }


def test_the_lookup_has_no_address_with_store_ip_off(
    secondary_storage, accounts_storage, session_storage
) -> None:
    auth = make_auth(
        secondary_storage,
        accounts_storage,
        session_storage,
        config={"session": {"store_ip": False}},
    )
    device = TestClient(make_app(auth), client=(DEVICE_IP, 50000))

    codes = start(device)

    authorization = auth.get_device_authorization(codes["user_code"])
    assert authorization is not None
    assert authorization.ip is None
    assert not any(DEVICE_IP in value for value, _ in secondary_storage.data.values())


def test_the_lookup_needs_a_signed_in_user(
    device: TestClient, browser: TestClient
) -> None:
    codes = start(device)

    response = browser.get("/device", params={"user_code": codes["user_code"]})

    assert response.status_code == 401
    assert response.json()["error"] == "unauthorized"


@pytest.mark.parametrize(
    "typed",
    [
        pytest.param(lambda code: code, id="as shown"),
        pytest.param(lambda code: code.lower(), id="lowercase"),
        pytest.param(lambda code: code.replace("-", ""), id="no separator"),
        pytest.param(lambda code: code.replace("-", " "), id="space"),
        pytest.param(
            lambda code: f"  {code.replace('-', '–')}\n", id="pasted with a dash"
        ),
        pytest.param(lambda code: " ".join(code.replace("-", "")), id="spaced out"),
    ],
)
def test_user_codes_ignore_case_and_separators(
    auth: CrossAuth, device: TestClient, typed: Callable[[str], str]
) -> None:
    codes = start(device)

    assert auth.get_device_authorization(typed(codes["user_code"])) is not None


@pytest.mark.parametrize(
    "user_code",
    ["", "BCDF-GHJ", "BCDF-GHJKL", "BCDF-GHJA", "BCDF-GHJ1", "B" * 65],
)
def test_strings_that_cannot_be_user_codes_are_rejected(user_code: str) -> None:
    assert normalize_user_code(user_code) is None


def test_unknown_codes_are_not_found(
    auth: CrossAuth, device: TestClient, browser: TestClient, session_storage
) -> None:
    start(device)
    token = sign_in(session_storage)

    assert auth.get_device_authorization("BCDF-GHJK") is None
    response = lookup(browser, token, "BCDF-GHJK")
    assert error_of(response) == "invalid_user_code"
    assert error_of(lookup(browser, token, "")) == "invalid_request"


def test_a_new_user_code_never_reuses_a_pending_one(
    auth: CrossAuth, device: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A second request drawing the code of a pending one would point that
    # code at the second device: whoever approves it would approve a device
    # they never saw.
    draws = iter("BBBBBBBB" + "BBBBBBBB" + "CCCCCCCC")
    monkeypatch.setattr("cross_auth._device.secrets.choice", lambda _: next(draws))

    first = start(device)
    second = start(device)

    assert first["user_code"] == "BBBB-BBBB"
    assert second["user_code"] == "CCCC-CCCC"
    approved = auth.get_device_authorization("BBBB-BBBB")
    assert approved is not None


def test_user_codes_are_formatted_in_two_halves() -> None:
    assert format_user_code("BCDFGHJK") == "BCDF-GHJK"


# The flow, end to end


def test_the_device_signs_in_once_the_user_approves(
    auth: CrossAuth,
    device: TestClient,
    browser: TestClient,
    session_storage: MemorySessionStorage,
    clock,
) -> None:
    codes = start(device)
    assert error_of(poll(device, codes["device_code"])) == "authorization_pending"

    token = sign_in(session_storage)
    assert approve(browser, token, codes["user_code"]).status_code == 204
    wait(clock)
    response = poll(device, codes["device_code"])

    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    body = response.json()
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == 86400
    authenticated = auth.authenticate_session_token(body["access_token"])
    assert authenticated is not None
    assert authenticated.user.id == "test"
    # The session describes the device, as other bearer logins do.
    record = authenticated.session
    assert record.login_method == "device"
    assert record.client_id == "cli"
    assert record.client_name == "Example CLI"
    assert record.user_agent == DEVICE_USER_AGENT
    assert record.ip == DEVICE_IP
    assert device_sessions(session_storage) == [record]


def test_the_application_can_approve_from_its_own_page(
    auth: CrossAuth, device: TestClient, session_storage, clock
) -> None:
    codes = start(device)

    assert auth.approve_device_authorization(codes["user_code"], user_id="test")
    wait(clock)
    response = poll(device, codes["device_code"])

    assert response.status_code == 200
    [record] = device_sessions(session_storage)
    assert record.user_id == "test"


def test_a_prefixed_session_token_is_identifiable(
    secondary_storage, accounts_storage, session_storage, clock
) -> None:
    auth = make_auth(
        secondary_storage,
        accounts_storage,
        session_storage,
        config={"session": {"token_prefix": "example"}},
    )
    device = TestClient(make_app(auth))
    codes = start(device)
    auth.approve_device_authorization(codes["user_code"], user_id="test")
    wait(clock)

    token = poll(device, codes["device_code"]).json()["access_token"]

    assert token.startswith("example_")
    assert auth.identify_token(token) == "session"


def test_a_token_issuer_mints_the_device_token(
    secondary_storage, accounts_storage, clock
) -> None:
    requests: list[TokenIssueRequest] = []

    def issue(request: TokenIssueRequest) -> tuple[str, int]:
        requests.append(request)
        return "minted", 600

    # Without session storage, the approval routes need a session to resolve
    # the user and are not mounted; the methods still approve.
    auth = make_auth(
        secondary_storage,
        accounts_storage,
        None,
        oauth_server_options={"token_issuer": issue},
    )
    device = TestClient(make_app(auth))
    codes = start(device, scope="deploy")
    assert device.post("/device/approve", json={}).status_code == 404
    auth.approve_device_authorization(codes["user_code"], user_id="test")
    wait(clock)

    response = poll(device, codes["device_code"])

    assert response.json()["access_token"] == "minted"
    [request] = requests
    assert request.grant_type == "device_code"
    assert request.login_method == "device"
    assert request.user_id == "test"
    assert request.client_id == "cli"
    assert request.scope == "deploy"


# Errors at /token


def test_errors_have_the_token_endpoints_shape(device: TestClient) -> None:
    codes = start(device)

    response = poll(device, codes["device_code"])

    assert response.status_code == 400
    assert response.json() == {
        "error": "authorization_pending",
        "error_description": "The user has not approved the request yet",
    }


def test_a_denied_request_ends_with_access_denied(
    auth: CrossAuth,
    device: TestClient,
    browser: TestClient,
    session_storage,
    secondary_storage,
    clock,
) -> None:
    codes = start(device)
    token = sign_in(session_storage)

    assert deny(browser, token, codes["user_code"]).status_code == 204
    response = poll(device, codes["device_code"])

    assert response.json() == {
        "error": "access_denied",
        "error_description": "The user denied the request",
    }
    wait(clock)
    assert error_of(poll(device, codes["device_code"])) == "expired_token"
    assert error_of(lookup(browser, token, codes["user_code"])) == "invalid_user_code"
    assert device_sessions(session_storage) == []
    assert secondary_storage.device_entries() == {}


def test_an_expired_request_ends_with_expired_token(
    device: TestClient, session_storage, clock
) -> None:
    codes = start(device)
    clock.shift(timedelta(seconds=900))

    assert error_of(poll(device, codes["device_code"])) == "expired_token"


def test_an_approval_the_device_polls_for_too_late_expires(
    auth: CrossAuth, device: TestClient, session_storage, clock
) -> None:
    codes = start(device)
    auth.approve_device_authorization(codes["user_code"], user_id="test")
    clock.shift(timedelta(seconds=901))

    assert error_of(poll(device, codes["device_code"])) == "expired_token"
    assert device_sessions(session_storage) == []


def test_an_unknown_device_code_is_expired_token(device: TestClient) -> None:
    start(device)

    assert error_of(poll(device, "not-a-device-code")) == "expired_token"


def test_a_device_code_works_only_for_its_client(
    auth: CrossAuth, device: TestClient, session_storage, clock
) -> None:
    codes = start(device)
    auth.approve_device_authorization(codes["user_code"], user_id="test")

    response = poll(device, codes["device_code"], client_id="other-cli")

    assert error_of(response) == "invalid_grant"
    assert response.json()["error_description"] == (
        "The device code was issued to another client"
    )
    # The other client's attempt doesn't consume the approval.
    wait(clock)
    assert poll(device, codes["device_code"]).status_code == 200


@pytest.mark.parametrize(
    ("form", "error"),
    [
        ({"client_id": "cli"}, "invalid_request"),
        ({"device_code": "x"}, "invalid_request"),
        ({"client_id": "unknown", "device_code": "x"}, "invalid_client"),
    ],
)
def test_malformed_polls_are_refused(
    device: TestClient, form: dict[str, str], error: str
) -> None:
    response = device.post("/token", data={"grant_type": GRANT_TYPE, **form})

    assert error_of(response) == error


def test_a_client_removed_since_the_request_gets_nothing(
    secondary_storage, accounts_storage, session_storage
) -> None:
    registered = dict(CLIENTS)
    auth = make_auth(
        secondary_storage, accounts_storage, session_storage, get_client=registered.get
    )
    device = TestClient(make_app(auth))
    codes = start(device)
    del registered["cli"]

    assert auth.get_device_authorization(codes["user_code"]) is None
    assert not auth.approve_device_authorization(codes["user_code"], user_id="test")
    assert error_of(poll(device, codes["device_code"])) == "invalid_client"


# slow_down


def test_polling_faster_than_the_interval_slows_the_device_down(
    device: TestClient, clock
) -> None:
    codes = start(device)
    # The first poll may come at once.
    assert error_of(poll(device, codes["device_code"])) == "authorization_pending"

    wait(clock, 4)
    response = poll(device, codes["device_code"])
    assert response.json() == {
        "error": "slow_down",
        "error_description": "Wait 10 seconds between polls",
    }

    # The interval is now 10 seconds, for this and every later poll.
    wait(clock, 10)
    assert error_of(poll(device, codes["device_code"])) == "authorization_pending"
    wait(clock, 10)
    assert error_of(poll(device, codes["device_code"])) == "authorization_pending"
    wait(clock, 5)
    # Each slow_down adds five seconds more.
    assert poll(device, codes["device_code"]).json()["error_description"] == (
        "Wait 15 seconds between polls"
    )


def test_slow_down_does_not_consume_the_approval(
    auth: CrossAuth, device: TestClient, session_storage, clock
) -> None:
    codes = start(device)
    assert error_of(poll(device, codes["device_code"])) == "authorization_pending"
    auth.approve_device_authorization(codes["user_code"], user_id="test")

    assert error_of(poll(device, codes["device_code"])) == "slow_down"
    assert device_sessions(session_storage) == []
    wait(clock, 10)
    assert poll(device, codes["device_code"]).status_code == 200


# Races. Each staged competitor runs between two storage operations of
# another request; at most one session may come out of it.


def test_two_approvals_cannot_both_win(
    auth: CrossAuth, device: TestClient, other_user, session_storage, clock
) -> None:
    codes = start(device)
    inner: list[bool] = []

    @auth.before("device.approve")
    def race(event: BeforeDeviceApproveEvent) -> None:
        if event.user_id == "test":
            inner.append(
                auth.approve_device_authorization(codes["user_code"], user_id="other")
            )

    outer = auth.approve_device_authorization(codes["user_code"], user_id="test")

    assert (inner, outer) == ([True], False)
    wait(clock)
    assert poll(device, codes["device_code"]).status_code == 200
    [record] = device_sessions(session_storage)
    assert record.user_id == "other"


def test_an_approval_after_expiry_fails(
    auth: CrossAuth, device: TestClient, browser: TestClient, session_storage, clock
) -> None:
    codes = start(device)
    token = sign_in(session_storage)
    clock.shift(timedelta(seconds=900))

    assert error_of(approve(browser, token, codes["user_code"])) == "invalid_user_code"
    assert not auth.approve_device_authorization(codes["user_code"], user_id="test")
    assert error_of(poll(device, codes["device_code"])) == "expired_token"
    assert device_sessions(session_storage) == []


def test_a_deny_after_an_approval_is_refused(
    auth: CrossAuth, device: TestClient, browser: TestClient, session_storage, clock
) -> None:
    codes = start(device)
    token = sign_in(session_storage)
    assert approve(browser, token, codes["user_code"]).status_code == 204

    assert error_of(deny(browser, token, codes["user_code"])) == "invalid_user_code"
    assert not auth.deny_device_authorization(codes["user_code"], user_id="test")
    assert poll(device, codes["device_code"]).status_code == 200


def test_an_approval_after_a_deny_is_refused(
    auth: CrossAuth, device: TestClient, browser: TestClient, session_storage
) -> None:
    codes = start(device)
    token = sign_in(session_storage)
    assert auth.deny_device_authorization(codes["user_code"], user_id="test")

    assert error_of(approve(browser, token, codes["user_code"])) == "invalid_user_code"
    assert error_of(poll(device, codes["device_code"])) == "access_denied"
    assert device_sessions(session_storage) == []


def test_a_poll_after_the_token_was_handed_out_gets_expired_token(
    auth: CrossAuth, device: TestClient, session_storage, secondary_storage, clock
) -> None:
    codes = start(device)
    auth.approve_device_authorization(codes["user_code"], user_id="test")
    assert poll(device, codes["device_code"]).status_code == 200

    wait(clock)
    assert error_of(poll(device, codes["device_code"])) == "expired_token"
    assert len(device_sessions(session_storage)) == 1
    assert secondary_storage.device_entries() == {}


def test_a_poll_racing_the_one_that_gets_the_token_gets_no_session(
    auth: CrossAuth, device: TestClient, secondary_storage, session_storage, clock
) -> None:
    codes = start(device)
    auth.approve_device_authorization(codes["user_code"], user_id="test")
    competing: list[httpx.Response] = []

    def race() -> None:
        wait(clock)
        competing.append(poll(device, codes["device_code"]))

    # Right after the first poll took the decision, before it ends the request.
    secondary_storage.after_pop["oauth:device:decision:"] = race

    response = poll(device, codes["device_code"])

    assert response.status_code == 200
    # The competitor finds the request but no decision: still pending to it.
    assert error_of(competing[0]) == "authorization_pending"
    wait(clock)
    assert error_of(poll(device, codes["device_code"])) == "expired_token"
    assert len(device_sessions(session_storage)) == 1


def test_a_poll_during_the_login_of_another_gets_expired_token(
    auth: CrossAuth, device: TestClient, session_storage, clock
) -> None:
    codes = start(device)
    auth.approve_device_authorization(codes["user_code"], user_id="test")
    competing: list[httpx.Response] = []

    @auth.before("login")
    def race(event: BeforeLoginEvent) -> None:
        wait(clock)
        competing.append(poll(device, codes["device_code"]))

    assert poll(device, codes["device_code"]).status_code == 200
    assert error_of(competing[0]) == "expired_token"
    assert len(device_sessions(session_storage)) == 1


def test_a_poll_during_an_approval_is_still_pending(
    auth: CrossAuth, device: TestClient, secondary_storage, session_storage, clock
) -> None:
    codes = start(device)
    during: list[httpx.Response] = []
    # Between the approval taking the user code and storing its decision.
    secondary_storage.after_pop["oauth:device:user_code:"] = lambda: during.append(
        poll(device, codes["device_code"])
    )

    assert auth.approve_device_authorization(codes["user_code"], user_id="test")

    assert error_of(during[0]) == "authorization_pending"
    wait(clock)
    assert poll(device, codes["device_code"]).status_code == 200
    assert len(device_sessions(session_storage)) == 1


def test_nothing_creates_a_session_but_the_poll(
    auth: CrossAuth, device: TestClient, session_storage, other_user
) -> None:
    approved = start(device)
    denied = start(device)
    abandoned = start(device)

    auth.approve_device_authorization(approved["user_code"], user_id="test")
    auth.deny_device_authorization(denied["user_code"], user_id="other")
    auth.get_device_authorization(abandoned["user_code"])

    assert session_storage.records == {}


# user_can_authenticate


@pytest.fixture
def refused() -> set[str]:
    return set()


@pytest.fixture
def guarded_auth(
    secondary_storage, accounts_storage, session_storage, refused: set[str]
) -> CrossAuth:
    return make_auth(
        secondary_storage,
        accounts_storage,
        session_storage,
        user_can_authenticate=lambda user: user.id not in refused,
    )


def test_a_refused_user_cannot_approve(
    guarded_auth: CrossAuth, session_storage, refused: set[str]
) -> None:
    device = TestClient(make_app(guarded_auth))
    browser = TestClient(make_app(guarded_auth))
    codes = start(device)
    token = sign_in(session_storage)
    refused.add("test")

    with pytest.raises(CrossAuthException) as raised:
        guarded_auth.approve_device_authorization(codes["user_code"], user_id="test")
    # The route resolves a refused user's session as no session.
    response = approve(browser, token, codes["user_code"])

    assert raised.value.error == "access_denied"
    assert response.status_code == 401
    # Still pending: the user can sign in with another account and approve.
    assert guarded_auth.get_device_authorization(codes["user_code"]) is not None


def test_a_user_refused_after_approving_gets_no_session(
    guarded_auth: CrossAuth, session_storage, refused: set[str], clock
) -> None:
    device = TestClient(make_app(guarded_auth))
    codes = start(device)
    guarded_auth.approve_device_authorization(codes["user_code"], user_id="test")
    refused.add("test")
    wait(clock)

    response = poll(device, codes["device_code"])

    assert response.json() == {
        "error": "access_denied",
        "error_description": "Sign-in is not allowed",
    }
    assert session_storage.records == {}
    wait(clock)
    assert error_of(poll(device, codes["device_code"])) == "expired_token"


# Hooks


def test_a_code_request_hook_attaches_metadata_the_lookup_returns(
    auth: CrossAuth, device: TestClient, browser: TestClient, session_storage
) -> None:
    started: list[AfterDeviceCodeEvent] = []

    @auth.before("device.code")
    def tag(event: BeforeDeviceCodeEvent) -> BeforeDeviceCodeEvent:
        return replace(
            event,
            metadata={
                "tool": event.request.headers.get("x-tool"),
                "version": int(event.request.post_data["version"]),
            },
        )

    auth.after("device.code")(started.append)

    response = device.post(
        "/device/code",
        data={"client_id": "cli", "version": "2"},
        headers={"X-Tool": "deploy"},
    )
    user_code = response.json()["user_code"]

    expected = {"tool": "deploy", "version": 2}
    assert (
        lookup(browser, sign_in(session_storage), user_code).json()["metadata"]
        == expected
    )
    [event] = started
    assert event.device_authorization.metadata == expected
    assert event.device_authorization.client_name == "Example CLI"


def test_a_code_request_hook_can_only_change_the_metadata(
    auth: CrossAuth, device: TestClient
) -> None:
    @auth.before("device.code")
    def retarget(event: BeforeDeviceCodeEvent) -> BeforeDeviceCodeEvent:
        return replace(event, client_id="other-cli")

    with pytest.raises(ValueError, match="only change metadata"):
        device.post("/device/code", data={"client_id": "cli"})


def test_a_code_request_hook_must_attach_json(
    auth: CrossAuth, device: TestClient
) -> None:
    @auth.before("device.code")
    def attach(event: BeforeDeviceCodeEvent) -> BeforeDeviceCodeEvent:
        return replace(event, metadata={"started": object()})

    with pytest.raises(TypeError, match="JSON metadata"):
        device.post("/device/code", data={"client_id": "cli"})


def test_a_code_request_hook_can_refuse(
    auth: CrossAuth, device: TestClient, secondary_storage
) -> None:
    @auth.before("device.code")
    def refuse(event: BeforeDeviceCodeEvent) -> None:
        raise CrossAuthException("unauthorized_client", "Not for this client")

    response = device.post("/device/code", data={"client_id": "cli"})

    assert response.json() == {
        "error": "unauthorized_client",
        "error_description": "Not for this client",
    }
    assert secondary_storage.data == {}


def test_approval_hooks_see_the_user_and_the_request(
    auth: CrossAuth, device: TestClient, browser: TestClient, session_storage
) -> None:
    before: list[BeforeDeviceApproveEvent] = []
    after: list[AfterDeviceApproveEvent] = []
    auth.before("device.approve")(before.append)
    auth.after("device.approve")(after.append)
    first = start(device)
    second = start(device)

    approve(browser, sign_in(session_storage), first["user_code"])
    auth.approve_device_authorization(second["user_code"], user_id="test")

    assert [event.user_id for event in before] == ["test", "test"]
    assert [event.user_id for event in after] == ["test", "test"]
    route, method = after
    assert isinstance(route.device_authorization, DeviceAuthorization)
    assert route.device_authorization.client_id == "cli"
    assert route.request is not None
    assert route.request.headers["user-agent"] == BROWSER_USER_AGENT
    assert method.request is None
    assert before[0].device_authorization == route.device_authorization


def test_an_approval_hook_that_refuses_leaves_the_request_pending(
    auth: CrossAuth, device: TestClient, browser: TestClient, session_storage
) -> None:
    @auth.before("device.approve")
    def refuse(event: BeforeDeviceApproveEvent) -> None:
        raise CrossAuthException("access_denied", "Approve from a work account", 403)

    codes = start(device)

    response = approve(browser, sign_in(session_storage), codes["user_code"])

    assert response.status_code == 403
    assert response.json() == {
        "error": "access_denied",
        "error_description": "Approve from a work account",
    }
    assert auth.get_device_authorization(codes["user_code"]) is not None
    assert error_of(poll(device, codes["device_code"])) == "authorization_pending"


def test_the_grant_runs_its_hooks_around_the_login(
    auth: CrossAuth, device: TestClient, clock
) -> None:
    trace: list[str] = []
    before: list[BeforeTokenDeviceCodeEvent] = []
    after: list[AfterTokenDeviceCodeEvent] = []
    logins: list[BeforeLoginEvent] = []

    @auth.before("token.device_code")
    def before_grant(event: BeforeTokenDeviceCodeEvent) -> None:
        trace.append("before:token.device_code")
        before.append(event)

    @auth.before("login")
    def before_login(event: BeforeLoginEvent) -> None:
        trace.append("before:login")
        logins.append(event)

    @auth.after("login")
    def after_login(event: AfterLoginEvent) -> None:
        trace.append("after:login")

    @auth.after("token.device_code")
    def after_grant(event: AfterTokenDeviceCodeEvent) -> None:
        trace.append("after:token.device_code")
        after.append(event)

    codes = start(device, scope="deploy")
    auth.approve_device_authorization(codes["user_code"], user_id="test")
    wait(clock)
    response = poll(device, codes["device_code"])

    assert trace == [
        "before:token.device_code",
        "before:login",
        "after:login",
        "after:token.device_code",
    ]
    assert before == [
        BeforeTokenDeviceCodeEvent(client_id="cli", user_id="test", scope="deploy")
    ]
    [login] = logins
    assert login.credential == "bearer"
    assert login.login_method == "device"
    assert login.metadata == {
        "client_id": "cli",
        "client_name": "Example CLI",
        "user_agent": DEVICE_USER_AGENT,
        "ip": DEVICE_IP,
    }
    [event] = after
    assert event.user_id == "test"
    assert event.device_authorization.scope == "deploy"
    assert event.token_response.access_token == response.json()["access_token"]
    assert codes["device_code"] not in repr(event)


def test_a_grant_hook_that_refuses_ends_the_request(
    auth: CrossAuth, device: TestClient, session_storage, clock
) -> None:
    @auth.before("token.device_code")
    def refuse(event: BeforeTokenDeviceCodeEvent) -> None:
        raise CrossAuthException("invalid_scope", "Deploy access is not enabled")

    codes = start(device, scope="deploy")
    auth.approve_device_authorization(codes["user_code"], user_id="test")

    response = poll(device, codes["device_code"])

    assert response.json() == {
        "error": "invalid_scope",
        "error_description": "Deploy access is not enabled",
    }
    assert session_storage.records == {}
    wait(clock)
    assert error_of(poll(device, codes["device_code"])) == "expired_token"


# Storage


def test_no_code_is_stored_in_plaintext(
    auth: CrossAuth, device: TestClient, browser: TestClient, session_storage, clock
) -> None:
    codes = start(device)
    in_clear = [
        codes["device_code"],
        codes["user_code"],
        codes["user_code"].replace("-", ""),
    ]

    def assert_hidden(storage: InterleavingStorage) -> None:
        entries = storage.device_entries()
        assert entries
        for key, value in entries.items():
            assert re.fullmatch(r"oauth:device:[a-z_]+:[0-9a-f]{64}", key)
            for code in in_clear:
                assert code not in key
                assert code not in value

    storage = auth._context.secondary_storage
    assert isinstance(storage, InterleavingStorage)
    assert_hidden(storage)
    poll(device, codes["device_code"])
    assert_hidden(storage)
    approve(browser, sign_in(session_storage), codes["user_code"])
    assert_hidden(storage)
    wait(clock)
    assert poll(device, codes["device_code"]).status_code == 200
    assert storage.device_entries() == {}


def test_every_key_expires_with_the_request(
    auth: CrossAuth, device: TestClient, secondary_storage, clock
) -> None:
    codes = start(device)
    wait(clock, 60)
    poll(device, codes["device_code"])
    wait(clock, 30)
    auth.approve_device_authorization(codes["user_code"], user_id="test")

    ttls = {
        key.split(":")[2]: secondary_storage.ttls[key]
        for key in secondary_storage.device_entries()
    }

    # Written later, a key gets what is left of the request's 900 seconds.
    assert ttls == {"request": 900, "poll": 840, "decision": 810}
