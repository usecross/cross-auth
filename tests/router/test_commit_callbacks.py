"""After hooks follow the commit of the storage that owns each write.

``TransactionalAccountsStorage`` and ``DeferredSessionStorage`` are test-only
simulations of adapters whose writes join an application transaction (the
semantics of Django's ``atomic``/``on_commit``). They are not a native Django
integration; that adapter needs its own tests against real nested ``atomic``
blocks.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from copy import deepcopy
from typing import get_args

import pytest
import respx
from cross_web import Cookie, Response as CrossWebResponse
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from sqlalchemy.exc import IntegrityError

from cross_auth._auth_flow import _create_user_with_identity, _update_social_account
from cross_auth._session import create_session, get_session
from cross_auth._storage import CommitCallback
from cross_auth._tokens import TokenIssueRequest
from cross_auth.fastapi import CrossAuth
from cross_auth.hooks import AfterLoginEvent, AfterLogoutEvent, BeforeLogoutEvent
from cross_auth.hooks._types import HookEventName
from tests.conftest import (
    TEST_PASSWORD,
    MemoryAccountsStorage,
    MemorySessionStorage,
)

from .conftest import mock_token_and_userinfo, start_provider_auth


class TransactionalAccountsStorage(MemoryAccountsStorage):
    """Writes inside ``atomic()`` commit, or roll back, with the outermost block."""

    def __init__(self, test_password_hash: str):
        super().__init__(test_password_hash)
        self._scopes: list[list[CommitCallback]] = []

    @contextmanager
    def atomic(self) -> Iterator[None]:
        snapshot = deepcopy(self.data)
        self._scopes.append([])
        try:
            yield
        except BaseException:
            self._scopes.pop()
            self.data = snapshot
            raise
        callbacks = self._scopes.pop()
        if self._scopes:
            # Releasing a savepoint hands its callbacks to the enclosing block.
            self._scopes[-1].extend(callbacks)
            return
        for callback in callbacks:
            callback()

    def on_commit(self, callback: CommitCallback) -> None:
        if self._scopes:
            self._scopes[-1].append(callback)
        else:
            callback()


class DeferredSessionStorage(MemorySessionStorage):
    """Holds commit callbacks until the test commits or rolls back the store."""

    def __init__(self):
        super().__init__()
        self.pending: list[CommitCallback] = []
        self._committed = deepcopy(self.records)

    def on_commit(self, callback: CommitCallback) -> None:
        self.pending.append(callback)

    def commit(self) -> None:
        self._committed = deepcopy(self.records)
        pending, self.pending = self.pending, []
        for callback in pending:
            callback()

    def rollback(self) -> None:
        self.records = deepcopy(self._committed)
        self.pending = []


@pytest.fixture
def accounts_storage(test_password_hash: str) -> TransactionalAccountsStorage:
    return TransactionalAccountsStorage(test_password_hash)


def _trace_after_hooks(auth: CrossAuth) -> list[str]:
    trace: list[str] = []
    for name in get_args(HookEventName):
        auth._context.hooks.register_after(
            name, lambda event, name=name: trace.append(name)
        )
    return trace


def _signup(auth: CrossAuth, subject: str):
    def identity(user):
        return {
            "user_id": user.id,
            "provider": "fake",
            "provider_user_id": subject,
            "access_token": None,
            "refresh_token": None,
            "access_token_expires_at": None,
            "refresh_token_expires_at": None,
            "scope": None,
            "user_info": {"id": subject},
            "provider_email": f"{subject}@example.com",
            "provider_email_verified": True,
            "is_login_method": True,
            "extra_fields": None,
        }

    return _create_user_with_identity(
        context=auth._context,
        user_info={"id": subject, "email": f"{subject}@example.com"},
        email=f"{subject}@example.com",
        email_verified=True,
        identity=identity,
    )


def _refresh(auth: CrossAuth, account, scope: str):
    return _update_social_account(
        context=auth._context,
        social_account=account,
        access_token="new-token",
        refresh_token=None,
        access_token_expires_at=None,
        refresh_token_expires_at=None,
        scope=scope,
        user_info={"id": account.provider_user_id},
        provider_email=account.provider_email,
        provider_email_verified=account.provider_email_verified,
    )


def test_account_hooks_wait_for_outermost_commit_and_skip_rolled_back_savepoints(
    auth: CrossAuth, accounts_storage: TransactionalAccountsStorage
):
    trace = _trace_after_hooks(auth)
    scopes: list[str | None] = []
    auth.after("social_account.update")(
        lambda event: scopes.append(event.social_account.scope)
    )

    with accounts_storage.atomic():
        _, account = _signup(auth, "alice")
        with pytest.raises(RuntimeError, match="savepoint"):
            with accounts_storage.atomic():
                _refresh(auth, account, "rolled-back")
                raise RuntimeError("savepoint")
        with accounts_storage.atomic():
            _refresh(auth, account, "kept")
        assert trace == []

    assert trace == ["user.create", "social_account.create", "social_account.update"]
    assert scopes == ["kept"]


def test_outer_rollback_runs_no_success_hooks(
    auth: CrossAuth, accounts_storage: TransactionalAccountsStorage
):
    trace = _trace_after_hooks(auth)

    with pytest.raises(RuntimeError, match="outer"):
        with accounts_storage.atomic():
            _signup(auth, "alice")
            raise RuntimeError("outer")

    assert trace == []
    assert accounts_storage.find_user_by_email("alice@example.com") is None


def test_after_hook_failure_at_commit_propagates_and_keeps_the_signup(
    auth: CrossAuth, accounts_storage: TransactionalAccountsStorage
):
    trace = _trace_after_hooks(auth)

    @auth.after("user.create")
    def fail(event):
        raise RuntimeError("welcome email failed")

    with pytest.raises(RuntimeError, match="welcome email failed"):
        with accounts_storage.atomic():
            _signup(auth, "alice")

    # The paired social_account.create hook does not run after the failure.
    assert trace == ["user.create"]
    assert accounts_storage.find_user_by_email("alice@example.com") is not None


@respx.mock
def test_sign_in_refuses_to_log_in_before_account_changes_commit(
    auth: CrossAuth,
    client: TestClient,
    accounts_storage: TransactionalAccountsStorage,
    session_storage: MemorySessionStorage,
):
    trace = _trace_after_hooks(auth)
    mock_token_and_userinfo(email="new@example.com", provider_user_id="new")
    _, state = start_provider_auth(client, "/fake/login")

    with pytest.raises(RuntimeError, match="uncommitted"):
        with accounts_storage.atomic():
            client.get("/fake/callback", params={"code": "code", "state": state})

    assert session_storage.records == {}
    assert trace == []
    assert accounts_storage.find_user_by_email("new@example.com") is None


@respx.mock
def test_sign_in_outside_a_transaction_runs_hooks_in_order(
    auth: CrossAuth, client: TestClient
):
    trace = _trace_after_hooks(auth)
    mock_token_and_userinfo(email="new@example.com", provider_user_id="new")
    _, state = start_provider_auth(client, "/fake/login")

    response = client.get("/fake/callback", params={"code": "code", "state": state})

    assert response.status_code == 302
    assert trace == [
        "user.create",
        "social_account.create",
        "login",
        "oauth.callback",
    ]


def _password_grant(auth: CrossAuth):
    app = FastAPI()
    app.include_router(auth.router)
    with TestClient(app) as client:
        return client.post(
            "/token",
            data={
                "grant_type": "password",
                "client_id": "app-client",
                "username": "test@example.com",
                "password": TEST_PASSWORD,
            },
        )


def test_session_login_hooks_follow_the_session_store_commit(build_auth):
    session_storage = DeferredSessionStorage()
    auth = build_auth(session_storage=session_storage)
    trace = _trace_after_hooks(auth)

    response = _password_grant(auth)

    assert response.status_code == 200
    assert len(session_storage.records) == 1
    assert trace == []

    session_storage.commit()

    assert trace == ["login", "token.password"]


def test_token_issuer_logins_complete_when_the_issuer_returns(build_auth):
    session_storage = DeferredSessionStorage()

    def token_issuer(request: TokenIssueRequest) -> tuple[str, int]:
        return f"jwt-for-{request.user_id}", 900

    auth = build_auth(session_storage=session_storage, token_issuer=token_issuer)
    trace = _trace_after_hooks(auth)

    response = _password_grant(auth)

    assert response.json()["access_token"] == "jwt-for-test"
    assert trace == ["login", "token.password"]
    assert session_storage.pending == []


def _customize_response(event: AfterLoginEvent | AfterLogoutEvent) -> None:
    assert isinstance(event.response, CrossWebResponse)
    event.response.headers = {**(event.response.headers or {}), "X-After": "1"}
    event.response.cookies = [
        *(event.response.cookies or []),
        Cookie(name="after", value="1", secure=False),
    ]


def _cookie_app(auth: CrossAuth, session_storage: DeferredSessionStorage) -> TestClient:
    """Endpoints that commit the session store before returning the response."""
    app = FastAPI()

    @app.post("/login")
    def login() -> JSONResponse:
        response = JSONResponse({"ok": True})
        auth.login("test", response=response)
        session_storage.commit()
        return response

    @app.post("/logout")
    def logout(request: Request) -> JSONResponse:
        response = JSONResponse({"ok": True})
        auth.logout(request, response=response)
        session_storage.commit()
        return response

    return TestClient(app)


def test_cookie_login_refuses_a_deferring_session_store(build_auth):
    session_storage = DeferredSessionStorage()
    auth = build_auth(session_storage=session_storage)
    trace = _trace_after_hooks(auth)
    auth.after("login")(_customize_response)

    with pytest.raises(RuntimeError, match="commit before it returns"):
        _cookie_app(auth, session_storage).post("/login")

    session_storage.commit()
    assert session_storage.records == {}
    assert trace == []


@respx.mock
def test_browser_sign_in_refuses_a_deferring_session_store(
    build_auth, accounts_storage: TransactionalAccountsStorage
):
    session_storage = DeferredSessionStorage()
    auth = build_auth(session_storage=session_storage)
    trace = _trace_after_hooks(auth)
    app = FastAPI()
    app.include_router(auth.router)
    client = TestClient(app, follow_redirects=False)
    mock_token_and_userinfo(email="new@example.com", provider_user_id="new")
    _, state = start_provider_auth(client, "/fake/login")

    with pytest.raises(RuntimeError, match="commit before it returns"):
        client.get("/fake/callback", params={"code": "code", "state": state})

    session_storage.commit()
    assert session_storage.records == {}
    # The account was committed on its own; no login was issued for it.
    assert trace == ["user.create", "social_account.create"]
    assert accounts_storage.find_user_by_email("new@example.com") is not None


def test_logout_refuses_to_revoke_through_a_deferring_session_store(build_auth):
    session_storage = DeferredSessionStorage()
    auth = build_auth(session_storage=session_storage)
    token, record = create_session("test", session_storage)
    session_storage.commit()
    trace = _trace_after_hooks(auth)
    auth.after("logout")(_customize_response)

    with pytest.raises(RuntimeError, match="commit before it returns"):
        _cookie_app(auth, session_storage).post(
            "/logout", headers={"cookie": f"session_id={token}"}
        )

    session_storage.commit()
    assert get_session(token, session_storage) is not None
    assert session_storage.records[record.id].revoked_at is None
    assert trace == []


def test_logout_refuses_a_session_record_injected_by_a_before_hook(build_auth):
    session_storage = DeferredSessionStorage()
    auth = build_auth(session_storage=session_storage)
    token, record = create_session("test", session_storage)
    session_storage.commit()
    trace = _trace_after_hooks(auth)

    @auth.before("logout")
    def inject(event: BeforeLogoutEvent) -> BeforeLogoutEvent:
        return BeforeLogoutEvent(
            request=event.request, response=event.response, session_record=record
        )

    with pytest.raises(RuntimeError, match="commit before it returns"):
        _cookie_app(auth, session_storage).post("/logout")

    assert get_session(token, session_storage) is not None
    assert trace == []


def test_logout_without_a_session_runs_its_hooks_at_once(build_auth):
    session_storage = DeferredSessionStorage()
    auth = build_auth(session_storage=session_storage)
    trace = _trace_after_hooks(auth)
    auth.after("logout")(_customize_response)

    response = _cookie_app(auth, session_storage).post("/logout")

    # Nothing was written, so nothing waits for the store to commit.
    assert trace == ["logout"]
    assert response.headers["x-after"] == "1"
    cookies = response.headers.get_list("set-cookie")
    assert any(cookie.startswith("after=1") for cookie in cookies)
    assert any(cookie.startswith('session_id=""') for cookie in cookies)


def test_rolled_back_bearer_session_runs_no_hooks_and_cannot_be_used(build_auth):
    session_storage = DeferredSessionStorage()
    auth = build_auth(session_storage=session_storage)
    trace = _trace_after_hooks(auth)

    token, _ = auth.issue_session_token("test")
    session_storage.rollback()

    assert trace == []
    assert get_session(token, session_storage) is None


@pytest.mark.parametrize(
    "error",
    [
        RuntimeError("audit failed"),
        IntegrityError("INSERT INTO audit", {}, Exception("duplicate")),
    ],
    ids=["runtime", "integrity"],
)
@pytest.mark.parametrize("deferred", [False, True], ids=["immediate", "deferred"])
def test_bearer_login_hook_errors_propagate_when_they_run(build_auth, error, deferred):
    session_storage = DeferredSessionStorage() if deferred else MemorySessionStorage()
    auth = build_auth(session_storage=session_storage)

    @auth.after("login")
    def fail(event: AfterLoginEvent) -> None:
        raise error

    if deferred:
        assert isinstance(session_storage, DeferredSessionStorage)
        token, _ = auth.issue_session_token("test")
        with pytest.raises(type(error)) as raised:
            session_storage.commit()
    else:
        with pytest.raises(type(error)) as raised:
            auth.issue_session_token("test")

    # Raised as is, once, and the committed session stays.
    assert raised.value is error
    assert len(session_storage.records) == 1
    if deferred:
        assert get_session(token, session_storage) is not None
