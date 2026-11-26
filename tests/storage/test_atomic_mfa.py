"""A user's factor and recovery-code changes run one at a time."""

import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from threading import Barrier

import pytest
from sqlalchemy import event
from sqlalchemy.exc import OperationalError
from sqlmodel import Session, col, create_engine, select

from cross_auth.storage.sqlmodel import SQLModelMFAStorage

from .models import (
    AccountsStore,
    StoredMFAFactor,
    StoredRecoveryCode,
    UniqueRecoveryCode,
    UnlinkedMFAFactor,
    User,
)
from .support import user_data


def test_two_first_factors_at_once_issue_one_batch_of_codes(signup_engine):
    def session_factory():
        return Session(signup_engine)

    accounts = AccountsStore(session_factory=session_factory)
    user = accounts.create_user(**user_data(f"{uuid.uuid4().hex}@example.com"))
    store = SQLModelMFAStorage(
        StoredMFAFactor, StoredRecoveryCode, session_factory=session_factory
    )
    barrier = Barrier(2)

    def confirm(label):
        barrier.wait(timeout=10)
        _, first = store.create_factor(
            user_id=user.id,
            type="totp",
            name=label,
            data={},
            created_at=datetime.now(timezone.utc),
            recovery_code_hashes=[f"{label}-{index}" for index in range(3)],
        )
        return label if first else None

    with ThreadPoolExecutor(max_workers=2) as executor:
        firsts = [label for label in executor.map(confirm, "ab") if label]

    # Exactly one confirmation is the first factor, and its codes are the ones
    # stored: the other's codes would be shown to nobody.
    assert len(firsts) == 1
    with Session(signup_engine) as session:
        hashes = session.exec(
            select(StoredRecoveryCode.code_hash).where(
                col(StoredRecoveryCode.user_id) == user.id
            )
        ).all()
    assert sorted(hashes) == [f"{firsts[0]}-{index}" for index in range(3)]
    assert len(store.list_factors(user.id)) == 2


def test_the_factor_table_must_reference_the_user_table(signup_engine):
    with pytest.raises(TypeError, match="foreign key"):
        SQLModelMFAStorage(
            UnlinkedMFAFactor,
            StoredRecoveryCode,
            session_factory=lambda: Session(signup_engine),
        )


def test_each_model_may_bind_its_own_engine_if_both_share_one(signup_engine):
    accounts = AccountsStore(session_factory=lambda: Session(signup_engine))
    user = accounts.create_user(**user_data(f"{uuid.uuid4().hex}@example.com"))
    store = SQLModelMFAStorage(
        StoredMFAFactor,
        StoredRecoveryCode,
        # No default bind: the user-row lock resolves the factor model's.
        session_factory=lambda: Session(
            binds={StoredMFAFactor: signup_engine, StoredRecoveryCode: signup_engine}
        ),
    )

    _, first = store.create_factor(
        user_id=user.id,
        type="totp",
        name="Phone",
        data={},
        created_at=datetime.now(timezone.utc),
        recovery_code_hashes=["one"],
    )

    assert first
    assert store.count_recovery_codes(user.id) == 1


def test_factors_and_recovery_codes_must_share_a_database(signup_engine):
    other = create_engine("sqlite://")
    store = SQLModelMFAStorage(
        StoredMFAFactor,
        StoredRecoveryCode,
        session_factory=lambda: Session(
            binds={StoredMFAFactor: signup_engine, StoredRecoveryCode: other}
        ),
    )

    with pytest.raises(RuntimeError, match="one database"):
        store.create_factor(
            user_id=1,
            type="totp",
            name="Phone",
            data={},
            created_at=datetime.now(timezone.utc),
        )
    other.dispose()


def _store(engine, codes=StoredRecoveryCode):
    return SQLModelMFAStorage(
        StoredMFAFactor, codes, session_factory=lambda: Session(engine)
    )


def _user_with_a_factor(engine, store):
    accounts = AccountsStore(session_factory=lambda: Session(engine))
    user = accounts.create_user(**user_data(f"{uuid.uuid4().hex}@example.com"))
    store.create_factor(
        user_id=user.id,
        type="totp",
        name="Phone",
        data={},
        created_at=datetime.now(timezone.utc),
        recovery_code_hashes=["a", "b"],
    )
    return user


@pytest.mark.parametrize(
    "change",
    [
        lambda store, user_id: store.record_failure(user_id),
        lambda store, user_id: store.lock(user_id, until=datetime.now(timezone.utc)),
        lambda store, user_id: store.reset_failures(user_id),
    ],
    ids=["record_failure", "lock", "reset_failures"],
)
def test_lockout_changes_wait_for_the_user_lock(pg_engine, change):
    """A new factor copies the lockout state under the user lock, so changing
    that state must wait for it too, or the new factor keeps a stale copy."""
    user = _user_with_a_factor(pg_engine, _store(pg_engine))
    impatient = create_engine(
        pg_engine.url, connect_args={"options": "-c lock_timeout=200ms"}
    )
    try:
        with Session(pg_engine) as holder:
            holder.exec(
                select(User).where(col(User.id) == user.id).with_for_update()
            ).one()
            with pytest.raises(OperationalError, match="lock timeout"):
                change(_store(impatient), user.id)
    finally:
        impatient.dispose()


def test_record_failure_reports_the_count_it_made(signup_engine):
    """A reset right after the increment commits must not change the answer."""
    store = _store(signup_engine)
    user = _user_with_a_factor(signup_engine, store)
    resets = []

    def session_factory():
        session = Session(signup_engine)

        @event.listens_for(session, "after_commit")
        def reset_right_after(_session):
            if not resets:
                resets.append(True)
                store.reset_failures(user.id)

        return session

    racing = SQLModelMFAStorage(
        StoredMFAFactor, StoredRecoveryCode, session_factory=session_factory
    )

    assert racing.record_failure(user.id) == 1
    assert resets


def test_replacing_codes_keeps_a_hash_a_unique_table_already_has(signup_engine):
    store = _store(signup_engine, UniqueRecoveryCode)
    user = _user_with_a_factor(signup_engine, store)

    assert store.replace_recovery_codes(
        user.id, ["b", "c"], created_at=datetime.now(timezone.utc)
    )

    with Session(signup_engine) as session:
        hashes = session.exec(
            select(UniqueRecoveryCode.code_hash).where(
                col(UniqueRecoveryCode.user_id) == user.id
            )
        ).all()
    assert sorted(hashes) == ["b", "c"]
