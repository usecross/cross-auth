"""Two-factor authentication through the FastAPI router and ``CrossAuth``.

Every way of signing in must issue nothing until the second factor passes:
cookie and bearer logins, the password grant, and both OAuth callback flows.
Factors live in SQLModel tables, so this also covers ``SQLModelMFAStorage``.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import parse_qs, urlparse

import bcrypt
import pytest
import respx
import time_machine
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from sqlalchemy import JSON, Column
from sqlalchemy.pool import StaticPool
from sqlmodel import Field, Session, SQLModel, create_engine, select

from cross_web import Response as CrossWebResponse

from cross_auth import TokenIssueRequest, _totp
from cross_auth.exceptions import CrossAuthException, MFARequired
from cross_auth.fastapi import CrossAuth
from cross_auth.hooks import BeforeLoginEvent
from cross_auth.storage.sqlmodel import (
    SQLModelMFAFactor,
    SQLModelMFAStorage,
    SQLModelRecoveryCode,
)
from tests.conftest import TEST_PASSWORD, MemoryAccountsStorage, MemorySessionStorage
from tests.conftest import User as MemoryUser

from ..conftest import legacy_password_grant
from .conftest import (
    APP_OAUTH_SERVER,
    LEGACY_APP_OAUTH_SERVER,
    FakeProvider,
    mock_token_and_userinfo,
    start_provider_auth,
)

_CODE_CHALLENGE = "n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg"
_REDIRECT_URI = "http://client.example/cb"


class MFATestUser(SQLModel, table=True):
    """The row SQLModelMFAStorage locks; the users live in memory."""

    __tablename__ = "mfa_test_user"
    id: str = Field(primary_key=True)


class MFATestFactor(SQLModelMFAFactor, table=True):
    __tablename__ = "mfa_test_factor"
    id: int | None = Field(default=None, primary_key=True)
    user_id: str = Field(foreign_key="mfa_test_user.id", index=True)
    data: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))


class MFATestRecoveryCode(SQLModelRecoveryCode, table=True):
    __tablename__ = "mfa_test_recovery_code"
    id: int | None = Field(default=None, primary_key=True)
    user_id: str = Field(foreign_key="mfa_test_user.id", index=True)


@pytest.fixture(autouse=True)
def _start_of_a_totp_step() -> Iterator[None]:
    """Freeze each test one second into a TOTP step.

    The step a test enrolls in then lasts the whole test, so "this step's
    code" stays the code a replay check expects.
    """
    with time_machine.travel(
        datetime(2026, 1, 1, 12, 0, 1, tzinfo=timezone.utc), tick=False
    ):
        yield


@pytest.fixture
def engine() -> Iterator[Any]:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    SQLModel.metadata.create_all(
        engine,
        tables=[
            SQLModel.metadata.tables["mfa_test_user"],
            SQLModel.metadata.tables["mfa_test_factor"],
            SQLModel.metadata.tables["mfa_test_recovery_code"],
        ],
    )
    with Session(engine) as db:
        db.add(MFATestUser(id="test"))
        db.commit()
    yield engine
    engine.dispose()


@pytest.fixture
def auth(
    engine: Any,
    secondary_storage: Any,
    accounts_storage: MemoryAccountsStorage,
    session_storage: MemorySessionStorage,
    fake_provider: FakeProvider,
) -> CrossAuth:
    return make_auth(
        engine, secondary_storage, accounts_storage, session_storage, fake_provider
    )


def make_auth(
    engine: Any,
    secondary_storage: Any,
    accounts_storage: MemoryAccountsStorage,
    session_storage: MemorySessionStorage,
    fake_provider: FakeProvider,
    oauth_server: Any = LEGACY_APP_OAUTH_SERVER,
    requires_mfa: Callable[[Any, str | None], bool] | None = None,
    **mfa: Any,
) -> CrossAuth:
    return CrossAuth(
        providers=[fake_provider],
        storage=secondary_storage,
        accounts_storage=accounts_storage,
        session_storage=session_storage,
        config={
            "session": {"cookies": {"auth": True}},
            "mfa": {
                "issuer": "Acme",
                "secret_keys": ["test-key"],
                "verify_url": "/login/2fa",
                **mfa,
            },
        },
        mfa_storage=SQLModelMFAStorage(
            MFATestFactor,
            MFATestRecoveryCode,
            session_factory=lambda: Session(engine),
        ),
        oauth_server=oauth_server,
        requires_mfa=requires_mfa,
    )


def app_for(auth: CrossAuth) -> TestClient:
    app = FastAPI()
    app.include_router(auth.router)

    @app.post("/login")
    def login(request: Request, response: Response) -> Any:
        user = auth.authenticate("test@example.com", TEST_PASSWORD)
        assert user is not None
        try:
            auth.login(user.id, response=response, login_method="password")
        except MFARequired as required:
            return JSONResponse(
                {"challenge": required.challenge, "methods": required.methods},
                status_code=401,
            )
        return {"ok": True}

    @app.post("/login/2fa")
    def complete(request: Request, response: Response, body: dict[str, str]) -> Any:
        try:
            auth.complete_mfa_login(
                request, body["challenge"], response=response, code=body.get("code")
            )
        except CrossAuthException as error:
            return JSONResponse({"error": error.error}, status_code=error.status_code)
        return {"ok": True}

    @app.post("/settings/recovery-codes")
    def regenerate(request: Request) -> Any:
        try:
            return {"recovery_codes": auth.regenerate_recovery_codes(request)}
        except CrossAuthException as error:
            return JSONResponse({"error": error.error}, status_code=error.status_code)

    @app.post("/change-password")
    def change_password(request: Request) -> Any:
        auth.change_password(
            request, current_password=TEST_PASSWORD, new_password="a new password"
        )
        return {"ok": True}

    return TestClient(app, base_url="https://testserver", follow_redirects=False)


class PasswordAccountsStorage(MemoryAccountsStorage):
    """The memory accounts storage, able to store new passwords."""

    def set_password(self, user_id: Any, password: str) -> MemoryUser | None:
        user = self.find_user_by_id(user_id)
        if user is None:
            return None
        # Low cost, as for the test password: nothing checks this hash.
        salt = bcrypt.gensalt(rounds=4)
        user.hashed_password = bcrypt.hashpw(password.encode(), salt).decode()
        return user


def newest(session_storage: MemorySessionStorage) -> Any:
    # The clock is frozen, so the last session stored is the newest.
    return list(session_storage.records.values())[-1]


def code_now(secret: str, offset_steps: int = 0) -> str:
    step = _totp.time_step(datetime.now(tz=timezone.utc)) + offset_steps
    return _totp.code_at(secret, step)


def enroll(client: TestClient) -> tuple[str, list[str]]:
    """Turn on 2FA for the signed-in user; return the secret and the codes."""
    started = client.post("/mfa/totp/enroll", json={"name": "Phone"})
    assert started.status_code == 200, started.text
    secret = started.json()["secret"]
    confirmed = client.post(
        "/mfa/totp/confirm",
        json={
            "enrollment_id": started.json()["enrollment_id"],
            "code": code_now(secret),
        },
    )
    assert confirmed.status_code == 201, confirmed.text
    return secret, confirmed.json()["recovery_codes"]


@pytest.fixture
def enrolled(auth: CrossAuth) -> tuple[str, list[str]]:
    with app_for(auth) as client:
        assert client.post("/login").status_code == 200
        return enroll(client)


def test_totp_matches_rfc_6238() -> None:
    # RFC 6238 appendix B, SHA1, truncated to the 6 digits apps show.
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # "12345678901234567890"
    for timestamp, expected in [
        (59, "287082"),
        (1111111109, "081804"),
        (1234567890, "005924"),
        (20000000000, "353130"),
    ]:
        assert _totp.code_at(secret, timestamp // 30) == expected


def test_enrolling_gives_recovery_codes_and_revokes_other_sessions(
    auth: CrossAuth, session_storage: MemorySessionStorage, engine: Any
) -> None:
    with app_for(auth) as other, app_for(auth) as client:
        assert other.post("/login").status_code == 200
        assert client.post("/login").status_code == 200

        secret, codes = enroll(client)

        assert len(codes) == 10 and len(set(codes)) == 10
        with Session(engine) as db:
            hashes = db.exec(select(MFATestRecoveryCode.code_hash)).all()
            [factor] = db.exec(select(MFATestFactor)).all()
        assert not set(codes) & set(hashes)
        # The secret is stored encrypted.
        assert secret not in str(factor.data)
        assert other.get("/mfa").status_code == 401
        status = client.get("/mfa").json()
        assert status["enabled"] is True
        assert status["recovery_codes_remaining"] == 10


def test_cookie_login_waits_for_the_code(
    auth: CrossAuth,
    enrolled: tuple[str, list[str]],
    session_storage: MemorySessionStorage,
) -> None:
    secret, _ = enrolled
    with app_for(auth) as client:
        before = len(session_storage.records)
        paused = client.post("/login")
        assert paused.status_code == 401
        assert paused.json()["methods"] == ["totp", "recovery_code"]
        assert len(session_storage.records) == before
        challenge = paused.json()["challenge"]

        wrong = client.post(
            "/login/2fa", json={"challenge": challenge, "code": "000000"}
        )
        assert wrong.status_code == 400
        assert wrong.json()["error"] == "invalid_code"

        # This step's code was spent on enrolling; the next one is accepted.
        done = client.post(
            "/login/2fa", json={"challenge": challenge, "code": code_now(secret, 1)}
        )
        assert done.status_code == 200
        record = newest(session_storage)
        assert record.mfa_method == "totp"
        assert client.get("/mfa").status_code == 200
        # A challenge works once.
        again = client.post(
            "/login/2fa", json={"challenge": challenge, "code": code_now(secret, -1)}
        )
        assert again.status_code == 400
        assert again.json()["error"] == "invalid_challenge"


def test_bearer_login_waits_and_a_code_works_once(
    auth: CrossAuth, enrolled: tuple[str, list[str]]
) -> None:
    secret, _ = enrolled
    # The enrollment used this step's code already.
    with pytest.raises(MFARequired) as first:
        auth.issue_session_token("test")
    assert first.value.challenge is not None
    with pytest.raises(CrossAuthException) as replayed:
        auth.verify_mfa(first.value.challenge, code=code_now(secret))
    assert replayed.value.error == "invalid_code"

    token, record = auth.verify_mfa(first.value.challenge, code=code_now(secret, 1))
    assert token and record.mfa_method == "totp"

    with pytest.raises(MFARequired) as second:
        auth.issue_session_token("test")
    assert second.value.challenge is not None
    with pytest.raises(CrossAuthException):
        auth.verify_mfa(second.value.challenge, code=code_now(secret, 1))


def test_recovery_codes_work_once(
    auth: CrossAuth, enrolled: tuple[str, list[str]]
) -> None:
    _, codes = enrolled
    with pytest.raises(MFARequired) as first:
        auth.issue_session_token("test")
    assert first.value.challenge is not None
    _, record = auth.verify_mfa(first.value.challenge, recovery_code=codes[0].upper())
    assert record.mfa_method == "recovery_code"
    assert auth.get_mfa_status_for("test").recovery_codes_remaining == 9

    with pytest.raises(MFARequired) as second:
        auth.issue_session_token("test")
    assert second.value.challenge is not None
    with pytest.raises(CrossAuthException) as used:
        auth.verify_mfa(second.value.challenge, recovery_code=codes[0])
    assert used.value.error == "invalid_code"


def test_a_challenge_ends_after_five_wrong_codes_and_the_account_locks_after_ten(
    auth: CrossAuth, enrolled: tuple[str, list[str]]
) -> None:
    secret, _ = enrolled
    for _ in range(2):
        with pytest.raises(MFARequired) as paused:
            auth.issue_session_token("test")
        assert paused.value.challenge is not None
        errors = []
        for _ in range(6):
            with pytest.raises(CrossAuthException) as wrong:
                auth.verify_mfa(paused.value.challenge, code="000000")
            errors.append(wrong.value.error)
        # The sixth try finds the challenge gone, and does not count.
        assert errors[-1] == "invalid_challenge"

    with pytest.raises(MFARequired) as paused:
        auth.issue_session_token("test")
    assert paused.value.challenge is not None
    with pytest.raises(CrossAuthException) as locked:
        auth.verify_mfa(paused.value.challenge, code=code_now(secret, 1))
    assert (locked.value.error, locked.value.status_code) == ("mfa_locked", 429)


def test_password_grant_needs_the_mfa_grant(
    auth: CrossAuth, enrolled: tuple[str, list[str]]
) -> None:
    secret, _ = enrolled
    issued: list[Any] = []
    auth.after("token.password")(issued.append)
    with app_for(auth) as client:
        with legacy_password_grant():
            paused = client.post(
                "/token",
                data={
                    "grant_type": "password",
                    "client_id": "app-client",
                    "username": "test@example.com",
                    "password": TEST_PASSWORD,
                },
            )
        assert paused.status_code == 403
        body = paused.json()
        assert body["error"] == "mfa_required"
        assert "access_token" not in body

        done = client.post(
            "/token",
            data={
                "grant_type": "urn:cross-auth:grant-type:mfa",
                "client_id": "app-client",
                "mfa_token": body["mfa_token"],
                "otp": code_now(secret, 1),
            },
        )
        assert done.status_code == 200, done.text
        assert done.json()["access_token"]
    # The hook a password grant without 2FA runs, without the password.
    [event] = issued
    assert (event.client_id, event.username) == ("app-client", "test@example.com")
    assert event.token_response.access_token == done.json()["access_token"]


def _link_identity(accounts_storage: MemoryAccountsStorage) -> None:
    accounts_storage.create_social_account(
        user_id="test",
        provider="fake",
        provider_user_id="fake-user-1",
        access_token=None,
        refresh_token=None,
        access_token_expires_at=None,
        refresh_token_expires_at=None,
        scope=None,
        user_info={},
        provider_email="test@example.com",
        provider_email_verified=True,
        is_login_method=True,
    )


@respx.mock
def test_provider_sign_in_goes_through_the_verify_page(
    auth: CrossAuth,
    enrolled: tuple[str, list[str]],
    accounts_storage: MemoryAccountsStorage,
    session_storage: MemorySessionStorage,
) -> None:
    secret, _ = enrolled
    _link_identity(accounts_storage)
    with app_for(auth) as client:
        mock_token_and_userinfo(email="test@example.com")
        _, state = start_provider_auth(client, "/fake/login")
        before = len(session_storage.records)
        callback = client.get("/fake/callback", params={"code": "c", "state": state})

        assert callback.status_code == 302
        assert callback.headers["location"] == "/login/2fa"
        assert "mfa_challenge" in client.cookies
        assert len(session_storage.records) == before

        verified = client.post("/mfa/verify", data={"code": code_now(secret, 1)})
        assert verified.status_code == 303
        assert verified.headers["location"] == "/"
        record = newest(session_storage)
        assert (record.login_method, record.mfa_method) == ("fake", "totp")


@respx.mock
def test_apps_can_skip_2fa_for_provider_sign_ins(
    engine: Any,
    secondary_storage: Any,
    accounts_storage: MemoryAccountsStorage,
    session_storage: MemorySessionStorage,
    fake_provider: FakeProvider,
    enrolled: tuple[str, list[str]],
) -> None:
    _link_identity(accounts_storage)
    relaxed = make_auth(
        engine,
        secondary_storage,
        accounts_storage,
        session_storage,
        fake_provider,
        require_for_providers=False,
    )
    with app_for(relaxed) as client:
        mock_token_and_userinfo(email="test@example.com")
        _, state = start_provider_auth(client, "/fake/login")
        callback = client.get("/fake/callback", params={"code": "c", "state": state})
        assert callback.status_code == 302
        assert callback.headers["location"] == "/"
        # Passwords are still challenged.
        assert client.post("/login").status_code == 401


@respx.mock
def test_client_sign_in_gets_its_code_only_after_2fa(
    auth: CrossAuth,
    enrolled: tuple[str, list[str]],
    accounts_storage: MemoryAccountsStorage,
) -> None:
    secret, _ = enrolled
    _link_identity(accounts_storage)
    with app_for(auth) as client:
        mock_token_and_userinfo(email="test@example.com")
        _, state = start_provider_auth(
            client,
            "/fake/authorize",
            params={
                "client_id": "app-client",
                "redirect_uri": _REDIRECT_URI,
                "response_type": "code",
                "code_challenge": _CODE_CHALLENGE,
                "code_challenge_method": "S256",
                "state": "client-state",
            },
        )
        callback = client.get("/fake/callback", params={"code": "c", "state": state})
        assert callback.headers["location"] == "/login/2fa"

        verified = client.post("/mfa/verify", json={"code": code_now(secret, 1)})
        assert verified.status_code == 200, verified.text
        redirect = urlparse(verified.json()["redirect_to"])
        params = parse_qs(redirect.query)
        assert params["state"] == ["client-state"]

        token = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": "app-client",
                "code": params["code"][0],
                "redirect_uri": _REDIRECT_URI,
                "code_verifier": "test",
            },
        )
        assert token.status_code == 200, token.text


def test_2fa_changes_need_a_recent_sign_in(
    auth: CrossAuth,
    enrolled: tuple[str, list[str]],
    session_storage: MemorySessionStorage,
) -> None:
    secret, _ = enrolled
    with app_for(auth) as client:
        challenge = client.post("/login").json()["challenge"]
        client.post(
            "/login/2fa", json={"challenge": challenge, "code": code_now(secret, 1)}
        )
        for record in session_storage.records.values():
            record.created_at -= timedelta(minutes=10)
        factor_id = client.get("/mfa").json()["factors"][0]["id"]

        refused = client.post(f"/mfa/factors/{factor_id}/remove", json={})
        assert refused.status_code == 403
        assert refused.json() == {
            "error": "reauthentication_required",
            "error_description": "Confirm it is you before changing two-factor authentication",
            "methods": ["password", "totp", "recovery_code", "sign_in_again"],
        }
        assert client.post("/mfa/recovery-codes", json={}).status_code == 403

        assert (
            client.post("/reauthenticate", json={"password": "nope"}).status_code == 400
        )
        assert (
            client.post("/reauthenticate", json={"password": TEST_PASSWORD}).status_code
            == 200
        )

        removed = client.post(f"/mfa/factors/{factor_id}/remove", json={})
        assert removed.json() == {
            "enabled": False,
            "factors": [],
            "recovery_codes_remaining": 0,
        }
        # 2FA is off: the next login needs no code.
        assert client.post("/login").status_code == 200


def test_a_challenge_is_held_while_its_code_is_checked(
    auth: CrossAuth, enrolled: tuple[str, list[str]]
) -> None:
    """A second request on the same challenge cannot spend another code."""
    _, codes = enrolled
    with pytest.raises(MFARequired) as paused:
        auth.issue_session_token("test")
    challenge = paused.value.challenge
    assert challenge is not None
    raced: list[str] = []

    @auth.after("mfa.verify")
    def race(event: Any) -> None:
        if raced or not event.success:
            return
        try:
            auth.verify_mfa(challenge, recovery_code=codes[1])
            raced.append("passed")
        except CrossAuthException as error:
            raced.append(error.error)

    _, record = auth.verify_mfa(challenge, recovery_code=codes[0])

    assert record.mfa_method == "recovery_code"
    assert raced == ["invalid_challenge"]
    # Only the winner's code is spent.
    assert auth.get_mfa_status_for("test").recovery_codes_remaining == 9


def test_codes_with_other_digits_are_wrong_codes(
    auth: CrossAuth, enrolled: tuple[str, list[str]]
) -> None:
    with pytest.raises(MFARequired) as paused:
        auth.issue_session_token("test")
    assert paused.value.challenge is not None
    with pytest.raises(CrossAuthException) as wrong:
        # Arabic-Indic digits pass str.isdigit().
        auth.verify_mfa(paused.value.challenge, code="١٢٣٤٥٦")
    assert wrong.value.error == "invalid_code"


def test_enrolling_refuses_a_name_the_factor_table_cannot_hold(
    auth: CrossAuth,
) -> None:
    with app_for(auth) as client:
        assert client.post("/login").status_code == 200
        refused = client.post("/mfa/totp/enroll", json={"name": "x" * 256})
        assert refused.status_code == 400
        assert refused.json()["error"] == "invalid_request"
        assert client.post("/mfa/totp/enroll", json={"name": "x" * 255}).is_success


def test_secret_keys_must_be_a_list(
    engine: Any,
    secondary_storage: Any,
    accounts_storage: MemoryAccountsStorage,
    session_storage: MemorySessionStorage,
    fake_provider: FakeProvider,
) -> None:
    with pytest.raises(ValueError, match="list of keys"):
        make_auth(
            engine,
            secondary_storage,
            accounts_storage,
            session_storage,
            fake_provider,
            secret_keys="test-key",
        )


def test_regenerating_codes_needs_a_factor_and_removal_takes_them(
    auth: CrossAuth, enrolled: tuple[str, list[str]], engine: Any
) -> None:
    with app_for(auth) as client:
        assert client.post("/login").status_code == 401
    store = SQLModelMFAStorage(
        MFATestFactor, MFATestRecoveryCode, session_factory=lambda: Session(engine)
    )
    [factor] = store.list_factors("test")
    assert store.delete_factor(user_id="test", factor_id=factor.id) == 0
    assert store.count_recovery_codes("test") == 0
    assert not store.replace_recovery_codes(
        "test", ["hash"], created_at=datetime.now(tz=timezone.utc)
    )
    assert store.count_recovery_codes("test") == 0


def test_only_the_first_factor_brings_recovery_codes(
    auth: CrossAuth, enrolled: tuple[str, list[str]], engine: Any
) -> None:
    secret, _ = enrolled
    # As if every code were used: a second factor still brings none.
    with Session(engine) as db:
        for row in db.exec(select(MFATestRecoveryCode)).all():
            db.delete(row)
        db.commit()
    created: list[Any] = []
    auth.after("mfa.factor.create")(created.append)
    with app_for(auth) as client:
        challenge = client.post("/login").json()["challenge"]
        client.post(
            "/login/2fa", json={"challenge": challenge, "code": code_now(secret, 1)}
        )
        started = client.post("/mfa/totp/enroll", json={"name": "Tablet"}).json()
        confirmed = client.post(
            "/mfa/totp/confirm",
            json={
                "enrollment_id": started["enrollment_id"],
                "code": code_now(started["secret"]),
            },
        )
    assert confirmed.status_code == 201, confirmed.text
    assert confirmed.json()["recovery_codes"] is None
    assert [event.enabled_mfa for event in created] == [False]
    assert auth.get_mfa_status_for("test").recovery_codes_remaining == 0


@respx.mock
def test_login_hooks_shape_the_verify_pages_response(
    auth: CrossAuth,
    enrolled: tuple[str, list[str]],
    accounts_storage: MemoryAccountsStorage,
) -> None:
    secret, _ = enrolled
    _link_identity(accounts_storage)

    @auth.before("login")
    def welcome(event: BeforeLoginEvent) -> BeforeLoginEvent:
        return replace(
            event,
            response=CrossWebResponse(
                status_code=303, headers={"Location": "/welcome", "X-Hook": "1"}
            ),
        )

    with app_for(auth) as client:
        mock_token_and_userinfo(email="test@example.com")
        _, state = start_provider_auth(client, "/fake/login")
        client.get("/fake/callback", params={"code": "c", "state": state})

        verified = client.post("/mfa/verify", data={"code": code_now(secret, 1)})

    assert verified.status_code == 303
    assert verified.headers["location"] == "/welcome"
    assert verified.headers["x-hook"] == "1"
    # The session cookie and the cleared challenge are still set.
    assert "mfa_challenge" not in client.cookies
    assert client.get("/mfa").status_code == 200


def test_enrolling_keeps_the_codes_when_sign_out_elsewhere_is_refused(
    auth: CrossAuth,
) -> None:
    @auth.before("session.revoke")
    def refuse(event: Any) -> None:
        raise CrossAuthException("access_denied", "Not now")

    with app_for(auth) as other, app_for(auth) as client:
        assert other.post("/login").status_code == 200
        assert client.post("/login").status_code == 200
        _, codes = enroll(client)

    assert len(codes) == 10


def test_the_mfa_grant_ends_with_the_password_grant(
    engine: Any,
    secondary_storage: Any,
    accounts_storage: MemoryAccountsStorage,
    session_storage: MemorySessionStorage,
    fake_provider: FakeProvider,
    enrolled: tuple[str, list[str]],
) -> None:
    secret, _ = enrolled
    stores = (engine, secondary_storage, accounts_storage, session_storage)
    with app_for(make_auth(*stores, fake_provider)) as client:
        with legacy_password_grant():
            paused = client.post(
                "/token",
                data={
                    "grant_type": "password",
                    "client_id": "app-client",
                    "username": "test@example.com",
                    "password": TEST_PASSWORD,
                },
            )
    mfa_token = paused.json()["mfa_token"]

    # The application turns the password grant off before the user answers.
    off = make_auth(*stores, fake_provider, oauth_server=APP_OAUTH_SERVER)
    with app_for(off) as client:
        refused = client.post(
            "/token",
            data={
                "grant_type": "urn:cross-auth:grant-type:mfa",
                "client_id": "app-client",
                "mfa_token": mfa_token,
                "otp": code_now(secret, 1),
            },
        )
    assert refused.status_code == 400
    assert refused.json()["error"] == "unsupported_grant_type"


def test_a_wrong_code_just_before_expiry_leaves_the_last_retry(
    auth: CrossAuth, enrolled: tuple[str, list[str]]
) -> None:
    secret, _ = enrolled
    with pytest.raises(MFARequired) as paused:
        auth.issue_session_token("test")
    challenge = paused.value.challenge
    assert challenge is not None

    # 0.8 s before the challenge's 300 s run out.
    with time_machine.travel(
        datetime.now(tz=timezone.utc) + timedelta(seconds=299.2), tick=False
    ):
        with pytest.raises(CrossAuthException) as wrong:
            auth.verify_mfa(challenge, code="000000")
        assert wrong.value.error == "invalid_code"
        _, record = auth.verify_mfa(challenge, code=code_now(secret))
    assert record.mfa_method == "totp"


# Revoking a user's sessions --------------------------------------------------
#
# Each of these is a way a user locks out someone who knows their password.
# They get the owner's client and the owner's session, which "others" keeps.


def _change_password(auth: CrossAuth, owner: TestClient, kept: Any) -> None:
    assert owner.post("/change-password").status_code == 200


def _revoke_all_sessions(auth: CrossAuth, owner: TestClient, kept: Any) -> None:
    auth.revoke_all_sessions(user_id="test")


def _revoke_other_sessions(auth: CrossAuth, owner: TestClient, kept: Any) -> None:
    auth.revoke_other_sessions(user_id="test", keep_session_id=kept.id)


def _sessions_route(auth: CrossAuth, owner: TestClient, kept: Any) -> None:
    assert owner.post("/sessions/revoke-others").status_code == 200


def _logout_everywhere(auth: CrossAuth, owner: TestClient, kept: Any) -> None:
    assert owner.post("/logout", json={"scope": "all"}).status_code == 204


@pytest.mark.parametrize(
    "revoke",
    [
        _change_password,
        _revoke_all_sessions,
        _revoke_other_sessions,
        _sessions_route,
        _logout_everywhere,
    ],
)
def test_revoking_the_users_sessions_ends_sign_ins_waiting_for_a_code(
    revoke: Callable[[CrossAuth, TestClient, Any], None],
    engine: Any,
    secondary_storage: Any,
    test_password_hash: str,
    session_storage: MemorySessionStorage,
    fake_provider: FakeProvider,
) -> None:
    """A sign-in that passed the password before the user locked others out
    holds no session yet, only its challenge: it must not finish either."""
    accounts = PasswordAccountsStorage(test_password_hash)
    auth = make_auth(
        engine, secondary_storage, accounts, session_storage, fake_provider
    )
    verified: list[Any] = []
    with app_for(auth) as owner, app_for(auth) as intruder:
        assert owner.post("/login").status_code == 200
        kept = newest(session_storage)
        secret, _ = enroll(owner)
        waiting = intruder.post("/login")
        assert waiting.status_code == 401
        auth.after("mfa.verify")(verified.append)

        # The intruder holds no session, so this may revoke none at all.
        revoke(auth, owner, kept)

        late = intruder.post(
            "/login/2fa",
            json={
                "challenge": waiting.json()["challenge"],
                "code": code_now(secret, 1),
            },
        )
    assert late.status_code == 400
    assert late.json()["error"] == "invalid_challenge"
    # Refused before the code was checked: it spent nothing and counted nothing.
    assert verified == []


def _paused(auth: CrossAuth) -> str:
    """Start a bearer sign-in for the test user; return its challenge."""
    with pytest.raises(MFARequired) as paused:
        auth.issue_session_token("test")
    assert paused.value.challenge is not None
    return paused.value.challenge


def test_a_sign_in_started_after_the_revocation_finishes(
    auth: CrossAuth, enrolled: tuple[str, list[str]]
) -> None:
    secret, _ = enrolled
    before = _paused(auth)

    auth.revoke_all_sessions(user_id="test")

    with pytest.raises(CrossAuthException) as revoked:
        auth.verify_mfa(before, code=code_now(secret, 1))
    assert revoked.value.error == "invalid_challenge"
    # With the code the revoked sign-in did not spend.
    _, record = auth.verify_mfa(_paused(auth), code=code_now(secret, 1))
    assert record.mfa_method == "totp"


def test_a_sign_in_started_after_the_revocation_outlives_its_marker(
    auth: CrossAuth, enrolled: tuple[str, list[str]], secondary_storage: Any
) -> None:
    """The revocation's marker expires with the challenges it revoked; one
    started after it must still finish once the marker is gone."""
    secret, _ = enrolled
    auth.revoke_all_sessions(user_id="test")
    after = _paused(auth)

    # Expired by hand: the memory storage's TTLs follow a clock that
    # time_machine does not move.
    [marker] = [key for key in secondary_storage.data if key.startswith("mfa:revoked:")]
    secondary_storage.delete(marker)

    _, record = auth.verify_mfa(after, code=code_now(secret, 1))
    assert record.mfa_method == "totp"


def test_revoking_one_session_leaves_sign_ins_waiting_for_a_code(
    auth: CrossAuth, enrolled: tuple[str, list[str]]
) -> None:
    """Signing out one device is about that device, not a lockout."""
    secret, codes = enrolled
    _, record = auth.verify_mfa(_paused(auth), recovery_code=codes[0])
    waiting = _paused(auth)

    assert auth.revoke_session(record.id, user_id="test")

    _, finished = auth.verify_mfa(waiting, code=code_now(secret, 1))
    assert finished.mfa_method == "totp"


# Custom token issuers -------------------------------------------------------


def make_session_issuer(
    engine: Any,
    secondary_storage: Any,
    accounts_storage: MemoryAccountsStorage,
    session_storage: MemorySessionStorage,
    fake_provider: FakeProvider,
) -> tuple[CrossAuth, list[TokenIssueRequest]]:
    """An app whose token_issuer issues Cross Auth sessions itself."""
    issued: list[TokenIssueRequest] = []

    def issue_token(request: TokenIssueRequest) -> tuple[str, int]:
        issued.append(request)
        token, _ = auth.issue_session_token(
            request.user_id,
            login_method=request.login_method,
            mfa_method=request.mfa_method,
        )
        return token, 3600

    auth = make_auth(
        engine,
        secondary_storage,
        accounts_storage,
        session_storage,
        fake_provider,
        oauth_server=replace(LEGACY_APP_OAUTH_SERVER, token_issuer=issue_token),
    )
    return auth, issued


@respx.mock
def test_a_token_issuer_issues_sessions_for_a_client_sign_in_that_passed_2fa(
    engine: Any,
    secondary_storage: Any,
    accounts_storage: MemoryAccountsStorage,
    session_storage: MemorySessionStorage,
    fake_provider: FakeProvider,
    enrolled: tuple[str, list[str]],
) -> None:
    """The callback asked for the code already; /token must not ask again."""
    secret, _ = enrolled
    _link_identity(accounts_storage)
    auth, issued = make_session_issuer(
        engine, secondary_storage, accounts_storage, session_storage, fake_provider
    )
    challenged: list[Any] = []
    auth.after("mfa.challenge")(challenged.append)
    with app_for(auth) as client:
        mock_token_and_userinfo(email="test@example.com")
        _, state = start_provider_auth(
            client,
            "/fake/authorize",
            params={
                "client_id": "app-client",
                "redirect_uri": _REDIRECT_URI,
                "response_type": "code",
                "code_challenge": _CODE_CHALLENGE,
                "code_challenge_method": "S256",
            },
        )
        client.get("/fake/callback", params={"code": "c", "state": state})
        verified = client.post("/mfa/verify", json={"code": code_now(secret, 1)})
        [code] = parse_qs(urlparse(verified.json()["redirect_to"]).query)["code"]

        token = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": "app-client",
                "code": code,
                "redirect_uri": _REDIRECT_URI,
                "code_verifier": "test",
            },
        )

    assert token.status_code == 200, token.text
    assert [request.mfa_method for request in issued] == ["totp"]
    record = newest(session_storage)
    assert (record.login_method, record.mfa_method) == ("fake", "totp")
    # Only the callback's challenge.
    assert len(challenged) == 1


def test_a_token_issuer_issues_sessions_after_the_mfa_grant(
    engine: Any,
    secondary_storage: Any,
    accounts_storage: MemoryAccountsStorage,
    session_storage: MemorySessionStorage,
    fake_provider: FakeProvider,
    enrolled: tuple[str, list[str]],
) -> None:
    secret, _ = enrolled
    auth, issued = make_session_issuer(
        engine, secondary_storage, accounts_storage, session_storage, fake_provider
    )
    with app_for(auth) as client:
        with legacy_password_grant():
            paused = client.post(
                "/token",
                data={
                    "grant_type": "password",
                    "client_id": "app-client",
                    "username": "test@example.com",
                    "password": TEST_PASSWORD,
                },
            )
        assert paused.status_code == 403
        done = client.post(
            "/token",
            data={
                "grant_type": "urn:cross-auth:grant-type:mfa",
                "client_id": "app-client",
                "mfa_token": paused.json()["mfa_token"],
                "otp": code_now(secret, 1),
            },
        )

    assert done.status_code == 200, done.text
    assert [request.mfa_method for request in issued] == ["totp"]
    record = newest(session_storage)
    assert (record.login_method, record.mfa_method) == ("password", "totp")


def test_a_client_cannot_claim_the_second_factor(
    engine: Any,
    secondary_storage: Any,
    accounts_storage: MemoryAccountsStorage,
    session_storage: MemorySessionStorage,
    fake_provider: FakeProvider,
    enrolled: tuple[str, list[str]],
) -> None:
    """mfa_method comes from Cross Auth's checked challenge, never the form."""
    auth, issued = make_session_issuer(
        engine, secondary_storage, accounts_storage, session_storage, fake_provider
    )
    with app_for(auth) as client, legacy_password_grant():
        claimed = client.post(
            "/token",
            data={
                "grant_type": "password",
                "client_id": "app-client",
                "username": "test@example.com",
                "password": TEST_PASSWORD,
                "mfa_method": "totp",
            },
        )

    assert claimed.status_code == 403
    assert claimed.json()["error"] == "mfa_required"
    assert issued == []


# Device logins -------------------------------------------------------------


def test_device_logins_are_not_challenged(
    auth: CrossAuth, enrolled: tuple[str, list[str]]
) -> None:
    """A device, such as a CLI, is approved from a browser where the user is
    signed in, past any second factor, and has nowhere to enter a code."""
    token, record = auth.issue_session_token("test", login_method="device")

    assert token
    assert (record.login_method, record.mfa_method) == ("device", None)
    # Every other sign-in still waits for its code.
    _paused(auth)
    with pytest.raises(MFARequired):
        auth.issue_session_token("test", login_method="password")


def test_a_rule_of_your_own_decides_for_device_logins_too(
    engine: Any,
    secondary_storage: Any,
    accounts_storage: MemoryAccountsStorage,
    session_storage: MemorySessionStorage,
    fake_provider: FakeProvider,
    enrolled: tuple[str, list[str]],
) -> None:
    strict = make_auth(
        engine,
        secondary_storage,
        accounts_storage,
        session_storage,
        fake_provider,
        requires_mfa=lambda user, login_method: True,
    )

    with pytest.raises(MFARequired):
        strict.issue_session_token("test", login_method="device")


# Recent authentication in a device login's session ---------------------------
#
# Each changes 2FA settings, which needs a recent sign-in or reauthentication.


def _start_enrollment(client: TestClient) -> Any:
    return client.post("/mfa/totp/enroll", json={"name": "Tablet"})


def _regenerate_codes(client: TestClient) -> Any:
    return client.post("/mfa/recovery-codes", json={})


def _regenerate_codes_from_the_app(client: TestClient) -> Any:
    # CrossAuth.regenerate_recovery_codes, which resolves the session itself.
    return client.post("/settings/recovery-codes")


def _remove_factor(client: TestClient) -> Any:
    factor_id = client.get("/mfa").json()["factors"][0]["id"]
    return client.post(f"/mfa/factors/{factor_id}/remove", json={})


CHANGES_TO_2FA = [
    _start_enrollment,
    _regenerate_codes,
    _regenerate_codes_from_the_app,
    _remove_factor,
]


@pytest.mark.parametrize("change", CHANGES_TO_2FA)
def test_a_device_logins_session_must_reauthenticate_before_changing_2fa(
    change: Callable[[TestClient], Any],
    auth: CrossAuth,
    enrolled: tuple[str, list[str]],
) -> None:
    """The device was approved from another session, perhaps a stolen one:
    signing in proved nothing in this one, so only reauthenticating counts."""
    secret, _ = enrolled
    token, _ = auth.issue_session_token("test", login_method="device")
    with app_for(auth) as client:
        client.headers["Authorization"] = f"Bearer {token}"

        refused = change(client)
        assert refused.status_code == 403
        assert refused.json()["error"] == "reauthentication_required"

        confirmed = client.post("/reauthenticate", json={"code": code_now(secret, 1)})
        assert confirmed.status_code == 200, confirmed.text
        allowed = change(client)
    assert allowed.status_code == 200, allowed.text


@pytest.mark.parametrize("change", CHANGES_TO_2FA)
def test_a_fresh_password_sign_in_may_change_2fa(
    change: Callable[[TestClient], Any],
    auth: CrossAuth,
    enrolled: tuple[str, list[str]],
) -> None:
    _, codes = enrolled
    with pytest.raises(MFARequired) as paused:
        auth.issue_session_token("test", login_method="password")
    assert paused.value.challenge is not None
    token, _ = auth.verify_mfa(paused.value.challenge, recovery_code=codes[0])
    with app_for(auth) as client:
        client.headers["Authorization"] = f"Bearer {token}"
        allowed = change(client)
    assert allowed.status_code == 200, allowed.text
