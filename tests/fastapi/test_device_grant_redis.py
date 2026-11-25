"""Real Redis proves a device request is decided once and its token issued once.

Two workers are held at the step that must be single use and let go together:
only Redis's atomic ``pop`` decides which one wins.
"""

import os
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from testcontainers.redis import RedisContainer

from cross_auth import DeviceGrant, OAuthServer
from cross_auth.fastapi import CrossAuth
from cross_auth.storage.redis import RedisStorage

from ..conftest import MemoryAccountsStorage, MemorySessionStorage
from ..conftest import User as MemoryUser
from .test_device_grant import CLIENTS, GRANT_TYPE, VERIFICATION_URI

# Steps that read or consume what a competing request may change.
RACED_GETS = ("oauth:device:poll:",)
RACED_POPS = ("oauth:device:user_code:", "oauth:device:decision:")


@pytest.fixture(scope="module")
def redis_client():
    container = RedisContainer("redis:7-alpine")
    try:
        container.start()
    except Exception as exc:
        if os.environ.get("CI"):
            raise
        pytest.skip(f"Docker unavailable for testcontainers: {exc}")
    try:
        yield container.get_client()
    finally:
        container.stop()


class RacingStorage(RedisStorage):
    """Holds two requests at each raced step while ``racing`` is set."""

    def __init__(self, client: Any) -> None:
        super().__init__(client)
        self.barrier = threading.Barrier(2)
        self.racing = False

    def get(self, key: str) -> str | None:
        if self.racing and key.startswith(RACED_GETS):
            self.barrier.wait(timeout=10)
        return super().get(key)

    def pop(self, key: str) -> str | None:
        if self.racing and key.startswith(RACED_POPS):
            self.barrier.wait(timeout=10)
        return super().pop(key)


@pytest.fixture
def storage(redis_client) -> RacingStorage:
    return RacingStorage(redis_client)


@pytest.fixture
def auth(
    storage: RacingStorage,
    accounts_storage: MemoryAccountsStorage,
    session_storage: MemorySessionStorage,
) -> CrossAuth:
    accounts_storage.data["other"] = MemoryUser(
        id="other",
        email="other@example.com",
        email_verified=True,
        hashed_password=None,
        social_accounts=[],
    )
    return CrossAuth(
        providers=[],
        storage=storage,
        accounts_storage=accounts_storage,
        session_storage=session_storage,
        oauth_server=OAuthServer(
            get_client=CLIENTS.get,
            device=DeviceGrant(verification_uri=VERIFICATION_URI),
        ),
    )


@pytest.fixture
def device(auth: CrossAuth) -> TestClient:
    app = FastAPI()
    app.include_router(auth.router)
    return TestClient(app)


def start(device: TestClient) -> dict[str, str]:
    return device.post("/device/code", data={"client_id": "cli"}).json()


def poll(device: TestClient, device_code: str) -> Any:
    return device.post(
        "/token",
        data={"grant_type": GRANT_TYPE, "client_id": "cli", "device_code": device_code},
    )


def test_only_one_of_two_concurrent_approvals_wins(
    auth: CrossAuth,
    device: TestClient,
    storage: RacingStorage,
    session_storage: MemorySessionStorage,
) -> None:
    codes = start(device)
    storage.racing = True

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(
            executor.map(
                lambda user_id: auth.approve_device_authorization(
                    codes["user_code"], user_id=user_id
                ),
                ["test", "other"],
            )
        )

    storage.racing = False
    assert sorted(results) == [False, True]
    winner = ["test", "other"][results.index(True)]
    assert poll(device, codes["device_code"]).status_code == 200
    [record] = session_storage.records.values()
    assert record.user_id == winner


def test_only_one_of_two_concurrent_polls_gets_a_token(
    auth: CrossAuth,
    device: TestClient,
    storage: RacingStorage,
    session_storage: MemorySessionStorage,
) -> None:
    codes = start(device)
    assert auth.approve_device_authorization(codes["user_code"], user_id="test")
    storage.racing = True

    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = list(
            executor.map(lambda _: poll(device, codes["device_code"]), range(2))
        )

    storage.racing = False
    assert sorted(response.status_code for response in responses) == [200, 400]
    [refused] = [response for response in responses if response.status_code == 400]
    assert refused.json()["error"] == "authorization_pending"
    assert len(session_storage.records) == 1
