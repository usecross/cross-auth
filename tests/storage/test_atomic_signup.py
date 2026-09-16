"""Signup is one transaction, including required application rows."""

import uuid
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from typing import Any

import pytest
from sqlalchemy import event, func
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, SQLModel, col, create_engine, select

from cross_auth.storage.sqlmodel import SQLModelAccountsStorage

from .models import SignupApplicationRow, SocialAccount, User
from .test_postgres import pg_engine  # noqa: F401


@pytest.fixture(params=["sqlite", "postgresql"])
def signup_engine(request, tmp_path):
    if request.param == "postgresql":
        yield request.getfixturevalue("pg_engine")
        return

    engine = create_engine(
        f"sqlite:///{tmp_path / 'signup.db'}",
        connect_args={"check_same_thread": False, "timeout": 10},
    )

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(connection, _record):
        connection.execute("PRAGMA foreign_keys=ON")

    SQLModel.metadata.create_all(engine)
    yield engine
    engine.dispose()


def row_counts(engine):
    with Session(engine) as session:
        return tuple(
            session.exec(select(func.count()).select_from(model)).one()
            for model in (User, SocialAccount, SignupApplicationRow)
        )


def user_data(email):
    return {
        "email": email,
        "email_verified": True,
        "user_info": {},
        "extra_fields": None,
    }


def identity_data(user, subject):
    assert user.id is not None
    return {
        "user_id": str(user.id),
        "provider": "github",
        "provider_user_id": subject,
        "access_token": "secret",
        "refresh_token": None,
        "access_token_expires_at": None,
        "refresh_token_expires_at": None,
        "scope": None,
        "user_info": {},
        "provider_email": user.email,
        "provider_email_verified": True,
        "is_login_method": True,
        "extra_fields": None,
    }


def make_store(engine, label, failure=None):
    class ApplicationStore(SQLModelAccountsStorage[User, SocialAccount]):
        def build_user(self, *, session, **kwargs):
            user = super().build_user(session=session, **kwargs)
            if failure == "user":
                setattr(user, "email", None)
            application_values: dict[str, Any] = {
                "user": user,
                "label": None if failure == "application" else label,
            }
            session.add(SignupApplicationRow(**application_values))
            return user

    return ApplicationStore(
        User, SocialAccount, session_factory=lambda: Session(engine)
    )


def test_atomic_signup_returns_detached_records(signup_engine):
    label = uuid.uuid4().hex
    store = make_store(signup_engine, label)

    user, account = store.create_user_with_identity(
        user=user_data(f"{label}@example.com"),
        identity=lambda user: identity_data(user, label),
    )

    assert account.user_id == user.id
    assert user.social_accounts[0].id == account.id
    assert account.access_token == "secret"
    with Session(signup_engine) as session:
        application = session.exec(
            select(SignupApplicationRow).where(SignupApplicationRow.label == label)
        ).one()
        assert application.user_id == user.id


@pytest.mark.parametrize(
    "failure", ["user", "application", "identity", "callback", "wrong_owner"]
)
def test_signup_failure_rolls_back_every_row(signup_engine, failure):
    label = uuid.uuid4().hex
    email = f"{label}@example.com"
    store = make_store(signup_engine, label, failure)
    before = row_counts(signup_engine)

    def identity(user):
        if failure == "callback":
            raise RuntimeError("hook rejected signup")
        data = identity_data(user, label)
        if failure == "identity":
            data["provider"] = None
        elif failure == "wrong_owner":
            data["user_id"] = -1
        return data

    error = (
        RuntimeError
        if failure == "callback"
        else ValueError
        if failure == "wrong_owner"
        else IntegrityError
    )
    match = {
        "callback": "hook rejected signup",
        "wrong_owner": "Initial identity must belong to the new user",
    }.get(failure)
    with pytest.raises(error, match=match):
        store.create_user_with_identity(user=user_data(email), identity=identity)

    assert row_counts(signup_engine) == before
    with Session(signup_engine) as session:
        assert session.exec(select(User).where(User.email == email)).first() is None
        assert (
            session.exec(
                select(SignupApplicationRow).where(SignupApplicationRow.label == label)
            ).first()
            is None
        )
        assert (
            session.exec(
                select(SocialAccount).where(SocialAccount.provider_user_id == label)
            ).first()
            is None
        )


def test_concurrent_signup_leaves_no_orphan_users(signup_engine):
    label = uuid.uuid4().hex
    store = make_store(signup_engine, label)
    barrier = Barrier(2)
    emails = [f"{label}-{index}@example.com" for index in range(2)]

    def signup(email):
        barrier.wait(timeout=10)
        try:
            return store.create_user_with_identity(
                user=user_data(email), identity=lambda user: identity_data(user, label)
            )
        except IntegrityError:
            return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(signup, emails))

    assert sum(result is not None for result in results) == 1
    with Session(signup_engine) as session:
        assert (
            len(session.exec(select(User).where(col(User.email).in_(emails))).all())
            == 1
        )
        assert (
            len(
                session.exec(
                    select(SignupApplicationRow).where(
                        SignupApplicationRow.label == label
                    )
                ).all()
            )
            == 1
        )
        assert (
            len(
                session.exec(
                    select(SocialAccount).where(SocialAccount.provider_user_id == label)
                ).all()
            )
            == 1
        )
