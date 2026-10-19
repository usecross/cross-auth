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
from fastapi import FastAPI
from fastapi.testclient import TestClient

from cross_auth._auth_flow import _create_user_with_identity, _update_social_account
from cross_auth._storage import CommitCallback
from cross_auth._tokens import TokenIssueRequest
from cross_auth.fastapi import CrossAuth
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
    """Holds commit callbacks until the test commits the session store."""

    def __init__(self):
        super().__init__()
        self.pending: list[CommitCallback] = []

    def on_commit(self, callback: CommitCallback) -> None:
        self.pending.append(callback)

    def commit(self) -> None:
        pending, self.pending = self.pending, []
        for callback in pending:
            callback()


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
