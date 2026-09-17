"""Disconnect decisions use current rows inside the deletion transaction."""

import uuid
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from sqlalchemy import event
from sqlmodel import Session, select

from .models import AccountsStore, SocialAccount, User
from .test_atomic_signup import identity_data, user_data
from . import test_atomic_signup
from .test_postgres import pg_engine  # noqa: F401


signup_engine = test_atomic_signup.signup_engine


@pytest.fixture
def disconnect_store(signup_engine):
    return AccountsStore(session_factory=lambda: Session(signup_engine))


def seed(store, *, password=False, login=True, alternative=None):
    user = store.create_user(**user_data(f"{uuid.uuid4().hex}@example.com"))
    if password:
        with store._open_session() as session:
            row = session.get(User, user.id)
            row.hashed_password = "usable-password-hash"
            session.commit()

    data = identity_data(user, uuid.uuid4().hex)
    data["is_login_method"] = login
    account = store.create_social_account(**data)
    other = None
    if alternative is not None:
        data = identity_data(user, uuid.uuid4().hex)
        data["provider"] = "google"
        data["is_login_method"] = alternative
        other = store.create_social_account(**data)
    return user, account, other


def disconnect(store, user, account, **overrides):
    return store.disconnect_social_account(
        **{
            "user_id": str(user.id),
            "social_account_id": str(account.id),
            "provider": account.provider,
            **overrides,
        }
    )


@pytest.mark.parametrize(
    ("password", "login", "alternative", "expected"),
    [
        (False, True, None, "last_login_method"),
        (False, True, False, "last_login_method"),
        (False, True, True, "disconnected"),
        (True, True, None, "disconnected"),
        (False, False, None, "disconnected"),
    ],
)
def test_current_login_methods_determine_disconnect(
    disconnect_store, password, login, alternative, expected
):
    store = disconnect_store
    user, account, _ = seed(
        store, password=password, login=login, alternative=alternative
    )

    assert disconnect(store, user, account) == expected
    assert (store.find_social_account_by_id(account.id) is None) == (
        expected == "disconnected"
    )


@pytest.mark.parametrize("mismatch", ["user", "provider", "invalid_id", "missing_id"])
def test_disconnect_requires_owned_provider_account(disconnect_store, mismatch):
    store = disconnect_store
    user, account, _ = seed(store, password=True)
    if mismatch == "user":
        other, _, _ = seed(store)
        overrides = {"user_id": other.id}
    elif mismatch == "provider":
        overrides = {"provider": "google"}
    else:
        overrides = {"social_account_id": "invalid" if mismatch == "invalid_id" else -1}

    assert disconnect(store, user, account, **overrides) == "not_found"
    assert store.find_social_account_by_id(account.id) is not None


@pytest.mark.parametrize("hidden", ["user", "target", "alternative"])
def test_disconnect_respects_query_filters(disconnect_store, signup_engine, hidden):
    store = disconnect_store
    user, account, _ = seed(store, alternative=True)

    class FilteredStore(AccountsStore):
        def filter_user_query(self, statement):
            return (
                statement.where(User.id != user.id) if hidden == "user" else statement
            )

        def filter_social_account_query(self, statement):
            if hidden == "target":
                return statement.where(SocialAccount.id != account.id)
            if hidden == "alternative":
                return statement.where(SocialAccount.provider == "github")
            return statement

    filtered = FilteredStore(session_factory=lambda: Session(signup_engine))

    assert disconnect(filtered, user, account) == (
        "last_login_method" if hidden == "alternative" else "not_found"
    )
    assert store.find_social_account_by_id(account.id) is not None


def test_concurrent_removals_keep_one_login_method(disconnect_store):
    store = disconnect_store
    user, first, second = seed(store, alternative=True)
    barrier = Barrier(2)

    def remove(account):
        barrier.wait(timeout=10)
        return disconnect(store, user, account)

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(remove, [first, second]))

    assert sorted(results) == ["disconnected", "last_login_method"]
    assert len(store.list_social_accounts(user_id=user.id)) == 1


def test_delete_failure_rolls_back(disconnect_store, signup_engine):
    store = disconnect_store
    user, account, _ = seed(store, password=True)

    def fail_delete(connection, cursor, statement, parameters, context, executemany):
        if statement.startswith("DELETE FROM socialaccount"):
            raise RuntimeError("delete failed")

    event.listen(signup_engine, "before_cursor_execute", fail_delete)
    try:
        with pytest.raises(RuntimeError, match="delete failed"):
            disconnect(store, user, account)
    finally:
        event.remove(signup_engine, "before_cursor_execute", fail_delete)

    assert store.find_social_account_by_id(account.id) is not None
    with Session(signup_engine) as session:
        assert (
            session.exec(select(User).where(User.id == user.id)).one().email
            == user.email
        )


def test_lock_does_not_run_column_onupdate(disconnect_store):
    store = disconnect_store
    user, account, _ = seed(store, password=True)
    before = store.find_user_by_id(user.id).updated_at

    assert disconnect(store, user, account) == "disconnected"

    assert store.find_user_by_id(user.id).updated_at == before


def test_lock_does_not_update_filtered_user(disconnect_store, signup_engine):
    user, account, _ = seed(disconnect_store, password=True)

    class FilteredStore(AccountsStore):
        def filter_user_query(self, statement):
            return statement.where(User.id != user.id)

    store = FilteredStore(session_factory=lambda: Session(signup_engine))
    updated_rows = []

    def record_update(connection, cursor, statement, parameters, context, executemany):
        if statement.startswith("UPDATE"):
            updated_rows.append(cursor.rowcount)

    event.listen(signup_engine, "after_cursor_execute", record_update)
    try:
        assert disconnect(store, user, account) == "not_found"
    finally:
        event.remove(signup_engine, "after_cursor_execute", record_update)

    assert updated_rows == [0]


def test_unusable_password_does_not_allow_last_login_removal(
    disconnect_store, monkeypatch
):
    user, account, _ = seed(disconnect_store, password=True)
    monkeypatch.setattr(User, "has_usable_password", property(lambda self: False))

    assert disconnect(disconnect_store, user, account) == "last_login_method"
    assert disconnect_store.find_social_account_by_id(account.id) is not None
