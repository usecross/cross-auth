"""Attachment policy runs against SQLite and real PostgreSQL transactions."""

import uuid
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from sqlalchemy.exc import IntegrityError, MultipleResultsFound
from sqlmodel import Session, SQLModel, create_engine
from sqlalchemy import event

from cross_auth.storage.sqlmodel import SQLModelAccountsStorage

from cross_auth.exceptions import CrossAuthException

from .models import ExclusiveAttachmentAccount, SharedAttachmentAccount, User
from .test_postgres import pg_engine  # noqa: F401 - shared PostgreSQL fixture


@pytest.fixture(
    params=[
        "sqlite-exclusive",
        "sqlite-shared",
        "postgresql-exclusive",
        "postgresql-shared",
    ]
)
def attachment_store(request, tmp_path):
    dialect, policy = request.param.split("-")
    if dialect == "postgresql":
        engine = request.getfixturevalue("pg_engine")
    else:
        engine = create_engine(
            f"sqlite:///{tmp_path / 'accounts.db'}",
            connect_args={"check_same_thread": False, "timeout": 10},
        )

        @event.listens_for(engine, "connect")
        def enable_foreign_keys(connection, _record):
            connection.execute("PRAGMA foreign_keys=ON")

        SQLModel.metadata.create_all(engine)

    model = (
        SharedAttachmentAccount if policy == "shared" else ExclusiveAttachmentAccount
    )
    yield SQLModelAccountsStorage(User, model, session_factory=lambda: Session(engine))

    if dialect == "sqlite":
        engine.dispose()


def create(store, owner, identity, *, login=False, **kwargs):
    return store.create_social_account(
        user_id=owner.id,
        provider="github",
        provider_user_id=identity,
        access_token=f"token-{owner.id}",
        refresh_token=None,
        access_token_expires_at=None,
        refresh_token_expires_at=None,
        scope=None,
        user_info={},
        provider_email=None,
        provider_email_verified=None,
        is_login_method=login,
        **kwargs,
    )


def owners(store):
    return [
        store.create_user(
            email=f"{uuid.uuid4().hex}@example.com",
            email_verified=True,
            user_info={},
        )
        for _ in range(2)
    ]


def test_shared_connection_preserves_login_owner(attachment_store):
    store = attachment_store
    if store.SocialAccountModel is ExclusiveAttachmentAccount:
        pytest.skip("Shared connections require the shared schema")
    personal, work = owners(store)
    identity = uuid.uuid4().hex

    login = create(store, personal, identity, login=True)
    connection = create(store, work, identity)

    assert store.has_social_account(provider="github", provider_user_id=identity)
    assert (
        store.find_social_account(
            provider="github", provider_user_id=identity, is_login_method=True
        ).id
        == login.id
    )
    assert (
        store.find_social_account(
            provider="github", provider_user_id=identity, user_id=str(work.id)
        ).id
        == connection.id
    )
    with pytest.raises(MultipleResultsFound):
        store.find_social_account(provider="github", provider_user_id=identity)

    store.delete_social_account(connection.id)

    remaining = store.find_social_account_by_id(login.id)
    assert remaining.access_token == f"token-{personal.id}"


def test_retries_do_not_promote_connections(attachment_store):
    store = attachment_store
    owner, _ = owners(store)
    identity = uuid.uuid4().hex
    original = create(store, owner, identity)

    assert create(store, owner, identity).id == original.id
    with pytest.raises(CrossAuthException, match="account_already_linked"):
        create(store, owner, identity, login=True)

    assert store.find_social_account_by_id(original.id).is_login_method is False


@pytest.mark.parametrize(
    ("login", "same_owner"), [(False, False), (True, False), (True, True)]
)
def test_concurrent_attachment(attachment_store, login, same_owner):
    store = attachment_store
    first, second = owners(store)
    identity = uuid.uuid4().hex
    barrier = Barrier(2)

    def attach(owner):
        barrier.wait(timeout=10)
        try:
            return create(store, owner, identity, login=login)
        except IntegrityError:
            return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(attach, [first, first if same_owner else second]))

    successful = [result for result in results if result is not None]
    shared = store.SocialAccountModel is SharedAttachmentAccount
    assert len(successful) == (2 if same_owner or (shared and not login) else 1)
    if same_owner:
        assert successful[0].id == successful[1].id


@pytest.mark.parametrize("same_owner", [False, True])
def test_database_constraints_protect_direct_writes(attachment_store, same_owner):
    store = attachment_store
    first, second = owners(store)
    identity = uuid.uuid4().hex
    create(store, first, identity, login=True)

    with store._open_session() as session:
        session.add(
            store.SocialAccountModel(
                user_id=first.id if same_owner else second.id,
                provider="github",
                provider_user_id=identity,
                is_login_method=not same_owner,
            )
        )

        with pytest.raises(IntegrityError):
            session.commit()


@pytest.mark.parametrize("violation", ["foreign_key", "not_null", "unrelated_unique"])
def test_unrelated_integrity_errors_propagate(attachment_store, violation):
    store = attachment_store
    first, second = owners(store)
    identity = uuid.uuid4().hex
    reference = uuid.uuid4().hex
    create(store, first, identity, extra_fields={"external_reference": reference})

    if violation == "foreign_key":
        second.id = -1
        kwargs = {}
    elif violation == "not_null":
        kwargs = {"extra_fields": {"external_reference": reference}}
        second.id = None
    else:
        kwargs = {"extra_fields": {"external_reference": reference}}

    with pytest.raises(IntegrityError):
        create(store, second, uuid.uuid4().hex, **kwargs)
