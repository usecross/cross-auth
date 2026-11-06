"""Run real example contracts without registering its SQLModel tables in pytest."""

import os
import subprocess
import sys
from pathlib import Path
from textwrap import dedent

EXAMPLE_DIR = Path(__file__).resolve().parents[1] / "examples" / "fastapi"


def run_fastapi_example(script: str) -> None:
    # The app creates its own tables and password user on import. A subprocess
    # keeps those model names and database state separate from adapter tests.
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("EXAMPLE_", "GOOGLE_", "GITHUB_EMULATOR_"))
    }
    result = subprocess.run(
        [sys.executable, "-c", dedent(script)],
        cwd=EXAMPLE_DIR,
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_example_secondary_storage_expiry_and_consumption() -> None:
    run_fastapi_example("""
        import main

        now = 100.0
        main.time.monotonic = lambda: now
        storage = main.MemorySecondaryStorage()
        storage.set("code", "first", ttl=10)
        assert storage.get("code") == "first"
        storage.set("code", "replacement", ttl=20)
        now = 110.0
        assert storage.get("code") == "replacement"
        assert storage.pop("code") == "replacement"
        assert storage.pop("code") is None
        storage.set("expired", "secret", ttl=1)
        now = 111.0
        assert storage.get("expired") is None
        assert storage.pop("expired") is None
        storage.set("expired-pop", "secret", ttl=0)
        assert storage.pop("expired-pop") is None
        storage.set("permanent", "value")
        now = 1000000.0
        assert storage.get("permanent") == "value"
        storage.delete("permanent")
        storage.delete("permanent")
        assert storage.get("permanent") is None
    """)


def test_example_secondary_storage_has_one_concurrent_consumer() -> None:
    run_fastapi_example("""
        from concurrent.futures import ThreadPoolExecutor
        import sys
        import threading
        from main import MemorySecondaryStorage

        storage = MemorySecondaryStorage()
        workers, attempts = 16, 1000
        ready = threading.Barrier(workers)
        # Exercise actual thread interleavings, not the GIL's usual long slice
        # that can accidentally make a read-then-delete implementation pass.
        sys.setswitchinterval(0.000001)
        for index in range(attempts):
            storage.set(str(index), "one-use-code", ttl=60)

        def consume(_):
            values = []
            for index in range(attempts):
                ready.wait(timeout=10)
                values.append(storage.pop(str(index)))
            return values

        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(consume, range(workers)))
        for index in range(attempts):
            values = [result[index] for result in results]
            assert values.count("one-use-code") == 1, (index, values)
            assert values.count(None) == workers - 1
    """)


def test_fastapi_example_password_session_and_bearer_revocation() -> None:
    run_fastapi_example("""
        from fastapi.testclient import TestClient
        from main import app

        with TestClient(app) as browser, TestClient(app) as bearer:
            assert browser.get("/api/me").status_code == 401
            login = browser.post("/login", data={
                "email": "demo+work@example.com", "password": "password123",
            }, follow_redirects=False)
            assert login.status_code == 303, login.text
            assert login.headers["location"] == "/profile"
            assert "cross_auth_example_session" in browser.cookies
            assert browser.get("/api/me").json()["email"] == "demo@example.com"
            token = bearer.post("/auth/token", data={
                "grant_type": "password", "client_id": "spa-example",
                "username": "demo@example.com", "password": "password123",
            })
            assert token.status_code == 200, token.text
            headers = {"Authorization": "Bearer " + token.json()["access_token"]}
            assert bearer.get("/api/me", headers=headers).status_code == 200
            assert browser.post("/api/sessions/revoke-all").status_code == 200
            assert bearer.get("/api/me", headers=headers).status_code == 401
            assert browser.get("/api/me").status_code == 401
    """)
