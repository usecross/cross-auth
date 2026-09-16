"""Real Redis proves callback and link-code consumption is atomic across workers."""

import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
import respx
from fastapi import FastAPI
from fastapi.testclient import TestClient
from testcontainers.redis import RedisContainer

from cross_auth.storage.redis import RedisStorage

from .conftest import mock_token_and_userinfo, start_provider_auth
from .test_link_flow import _store_link_code


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


@respx.mock
def test_only_one_concurrent_callback_succeeds(
    redis_client, build_auth, session_storage
):
    barrier = threading.Barrier(2)

    class RacingStorage(RedisStorage):
        def pop(self, key):
            barrier.wait(timeout=10)
            return super().pop(key)

    storage = RacingStorage(redis_client)
    app = FastAPI()
    app.include_router(build_auth(storage=storage).router)
    mock_token_and_userinfo(email="redis-race@example.com")
    with TestClient(app, follow_redirects=False) as browser:
        _, state = start_provider_auth(browser, "/fake/login")
        cookies = dict(browser.cookies)

    def callback():
        with TestClient(app, follow_redirects=False, cookies=cookies) as browser:
            return browser.get(
                "/fake/callback", params={"code": "code", "state": state}
            )

    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = list(executor.map(lambda _: callback(), range(2)))
    assert sorted(response.status_code for response in responses) == [302, 400]
    assert sum(bool(response.cookies.get("session_id")) for response in responses) == 1
    assert len(session_storage.records) == 1
    assert storage.get(f"oauth:authorization_request:v2:{state}") is None


@respx.mock
def test_only_one_concurrent_link_finalization_succeeds(redis_client, build_auth):
    barrier = threading.Barrier(2)

    class RacingStorage(RedisStorage):
        def pop(self, key):
            barrier.wait(timeout=10)
            return super().pop(key)

    storage = RacingStorage(redis_client)
    code = _store_link_code(storage, code="redis-link-race")
    app = FastAPI()
    app.include_router(
        build_auth(
            storage=storage, config={"account_linking": {"enabled": True}}
        ).router
    )
    mock_token_and_userinfo(email="test@example.com", provider_user_id="redis-linked")

    def finalize():
        with TestClient(app) as browser:
            return browser.post(
                "/fake/finalize-link",
                headers={"Authorization": "Bearer test"},
                json={
                    "link_code": code,
                    "code_verifier": "test",
                },
            )

    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = list(executor.map(lambda _: finalize(), range(2)))
    assert sorted(response.status_code for response in responses) == [200, 400]
    assert len(respx.calls) == 2  # One token exchange and one userinfo request.


def test_expired_redis_state_cannot_complete(redis_client, build_auth):
    storage = RedisStorage(redis_client)
    app = FastAPI()
    app.include_router(build_auth(storage=storage).router)
    with TestClient(app, follow_redirects=False) as browser:
        _, state = start_provider_auth(browser, "/fake/login")
        key = f"oauth:authorization_request:v2:{state}"
        assert 0 < redis_client.ttl(key) <= 600
        redis_client.pexpire(key, 1)
        time.sleep(0.02)
        response = browser.get(
            "/fake/callback", params={"code": "code", "state": state}
        )
        assert "error=session_expired" in response.headers["location"]
