"""A user's factor and recovery-code changes run one at a time."""

import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from threading import Barrier

import pytest
from sqlmodel import Session, col, select

from cross_auth.storage.sqlmodel import SQLModelMFAStorage

from .models import (
    AccountsStore,
    StoredMFAFactor,
    StoredRecoveryCode,
    UnlinkedMFAFactor,
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
