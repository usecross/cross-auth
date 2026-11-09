from sqlalchemy import event
from sqlalchemy.orm import object_session
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

from cross_auth._context import Context
from cross_auth._session import SessionConfig

from .models import (
    AccountsStore,
    DefaultLazyAccountsStore,
    DefaultLazyUser,
    SessionStore,
    User,
)


def _context(engine, accounts, secondary_storage, session: SessionConfig) -> Context:
    return Context(
        secondary_storage=secondary_storage,
        accounts_storage=accounts,
        session_storage=SessionStore(session_factory=lambda: Session(engine)),
        get_user_from_request=lambda _: None,
        config={"session": session},
    )


def test_authenticate_session_token_loads_the_user_in_the_db_session(
    engine, secondary_storage
):
    accounts = DefaultLazyAccountsStore(session_factory=lambda: Session(engine))
    user = accounts.create_user(
        user_info={}, email="session@example.com", email_verified=True
    )
    context = _context(engine, accounts, secondary_storage, {})
    token, record = context.create_session(str(user.id))

    with Session(engine) as db:
        result = context.authenticate_session_token(token, db_session=db)

        assert result is not None
        assert result.session.id == record.id
        user = result.user
        assert isinstance(user, DefaultLazyUser)
        assert object_session(user) is db
        # Loads lazily, which a user detached from its session could not do.
        assert user.social_accounts == []


def test_sliding_refresh_does_not_commit_the_callers_pending_work(
    secondary_storage,
):
    # A single shared connection: a commit anywhere commits everything on it.
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    SQLModel.metadata.create_all(engine)
    accounts = AccountsStore(session_factory=lambda: Session(engine))
    user = accounts.create_user(
        user_info={}, email="a@example.com", email_verified=True
    )
    context = _context(engine, accounts, secondary_storage, {"update_age": 0})
    token, _ = context.create_session(str(user.id))

    with Session(engine) as db:
        db.add(User(email="pending@example.com"))
        assert context.authenticate_session_token(token, db_session=db) is not None
        db.rollback()

    with Session(engine) as check:
        statement = select(User).where(User.email == "pending@example.com")
        assert check.exec(statement).first() is None


def test_sliding_refresh_does_not_wait_on_the_db_session_lock(
    tmp_path, secondary_storage
):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'auth.db'}", connect_args={"timeout": 1}
    )

    # SQLAlchemy's recipe for real SQLite transactions: a read takes a shared
    # lock that blocks another connection's commit until the read ends.
    @event.listens_for(engine, "connect")
    def disable_pysqlite_transactions(dbapi_connection, _record):
        dbapi_connection.isolation_level = None

    @event.listens_for(engine, "begin")
    def begin(connection):
        connection.exec_driver_sql("BEGIN")

    SQLModel.metadata.create_all(engine)
    accounts = AccountsStore(session_factory=lambda: Session(engine))
    user = accounts.create_user(
        user_info={}, email="a@example.com", email_verified=True
    )
    context = _context(engine, accounts, secondary_storage, {"update_age": 0})
    token, _ = context.create_session(str(user.id))

    with Session(engine) as db:
        result = context.authenticate_session_token(token, db_session=db)

    assert result is not None
    engine.dispose()
