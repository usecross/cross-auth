"""SQLModel operations commit before they return, so after hooks run at once.

The adapter owns one transaction per operation. A session joined to an
application transaction is rejected before anything is written, because its
commit would not make the write durable.
"""

import uuid

import pytest
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from cross_auth._auth_flow import _create_social_account, _create_user_with_identity
from cross_auth._context import Context
from cross_auth._login import issue_bearer_session
from cross_auth.hooks import HookRegistry
from tests.conftest import MemoryStorage

from .models import (
    AccountsStore,
    SessionStore,
    SignupApplicationRow,
    SocialAccount,
    User,
    UserSession,
)
from . import test_atomic_signup
from .test_atomic_signup import identity_data, make_store, row_counts

# Run against the same SQLite and PostgreSQL engines as the signup tests.
signup_engine = test_atomic_signup.signup_engine
pg_engine = test_atomic_signup.pg_engine


def make_context(store) -> tuple[Context, HookRegistry]:
    hooks = HookRegistry()
    context = Context(
        secondary_storage=MemoryStorage(),
        accounts_storage=store,
        get_user_from_request=lambda request: None,
        hooks=hooks,
    )
    return context, hooks


def signup(context: Context, label: str):
    return _create_user_with_identity(
        context=context,
        user_info={"id": label, "email": f"{label}@example.com"},
        email=f"{label}@example.com",
        email_verified=True,
        identity=lambda user: identity_data(user, label),
    )


def test_signup_hooks_run_after_user_identity_and_application_rows_commit(
    signup_engine,
):
    label = uuid.uuid4().hex
    context, hooks = make_context(make_store(signup_engine, label))
    seen = []

    def check_committed(event):
        # A separate session only sees committed rows.
        with Session(signup_engine) as session:
            user = session.exec(select(User).where(User.id == event.user.id)).one()
            seen.append(
                (
                    user.email,
                    session.exec(
                        select(SocialAccount).where(SocialAccount.user_id == user.id)
                    )
                    .one()
                    .provider_user_id,
                    session.exec(
                        select(SignupApplicationRow).where(
                            SignupApplicationRow.user_id == user.id
                        )
                    )
                    .one()
                    .label,
                )
            )

    hooks.register_after("user.create", check_committed)

    signup(context, label)

    assert seen == [(f"{label}@example.com", label, label)]


def test_session_joined_to_an_application_transaction_is_rejected(signup_engine):
    label = uuid.uuid4().hex
    before = row_counts(signup_engine)
    after_events = []

    with signup_engine.connect() as connection:
        outer = connection.begin()
        context, hooks = make_context(
            AccountsStore(session_factory=lambda: Session(connection))
        )
        hooks.register_after("user.create", after_events.append)

        with pytest.raises(RuntimeError, match="already in a transaction"):
            signup(context, label)

        assert outer.is_active
        outer.rollback()

    assert after_events == []
    assert row_counts(signup_engine) == before


def test_shared_session_in_a_transaction_is_rejected(signup_engine):
    label = uuid.uuid4().hex
    with Session(signup_engine) as shared:
        shared.exec(select(User)).all()
        store = AccountsStore(session_factory=lambda: shared)

        with pytest.raises(RuntimeError, match="already in a transaction"):
            store.find_user_by_email(f"{label}@example.com")

        # The application's session is left open for the application to end.
        assert shared.in_transaction()


def test_unrelated_application_transaction_does_not_hold_back_hooks(signup_engine):
    label = uuid.uuid4().hex
    context, hooks = make_context(make_store(signup_engine, label))
    after_events = []
    hooks.register_after("user.create", lambda event: after_events.append("user"))

    with signup_engine.connect() as other:
        outer = other.begin()
        signup(context, label)
        # Storage used its own connection, so the signup is already committed.
        assert after_events == ["user"]
        outer.rollback()

    with Session(signup_engine) as session:
        assert session.exec(
            select(User).where(User.email == f"{label}@example.com")
        ).one()


@pytest.mark.parametrize(
    "error",
    [
        RuntimeError("notification failed"),
        IntegrityError("INSERT INTO outbox", {}, Exception("duplicate")),
    ],
    ids=["runtime", "integrity"],
)
def test_after_hook_errors_propagate_without_rollback_or_retry(
    signup_engine, monkeypatch, error
):
    label = uuid.uuid4().hex
    store = make_store(signup_engine, label)
    context, hooks = make_context(store)
    user, _ = signup(context, label)

    creates = []
    create_social_account = store.create_social_account

    def counting_create(**kwargs):
        creates.append(kwargs["provider_user_id"])
        return create_social_account(**kwargs)

    monkeypatch.setattr(store, "create_social_account", counting_create)

    def fail(event):
        raise error

    hooks.register_after("social_account.create", fail)

    with pytest.raises(type(error)) as raised:
        _create_social_account(
            context=context,
            user_id=user.id,
            provider="gitlab",
            provider_user_id=f"{label}-second",
            access_token=None,
            refresh_token=None,
            access_token_expires_at=None,
            refresh_token_expires_at=None,
            scope=None,
            user_info={"id": f"{label}-second"},
            provider_email=None,
            provider_email_verified=None,
            is_login_method=False,
        )

    # Neither error is reinterpreted as an ownership conflict or retried.
    assert raised.value is error
    assert creates == [f"{label}-second"]
    with Session(signup_engine) as session:
        assert session.exec(
            select(SocialAccount).where(
                SocialAccount.provider_user_id == f"{label}-second"
            )
        ).one()


class RoutedSession(Session):
    """Routes every model to one connection, as a custom get_bind may."""

    def __init__(self, engine, connection):
        super().__init__(engine)
        self.connection = connection

    def get_bind(self, mapper=None, **kwargs):
        return self.connection


def _external_bindings(engine, connection):
    return {
        "mapped": lambda: Session(binds={User: connection, SocialAccount: connection}),
        "engine_with_mapped_overrides": lambda: Session(
            engine, binds={User: connection, SocialAccount: connection}
        ),
        "routed": lambda: RoutedSession(engine, connection),
    }


@pytest.mark.parametrize(
    "binding", ["mapped", "engine_with_mapped_overrides", "routed"]
)
def test_models_bound_to_an_application_transaction_are_rejected(
    signup_engine, binding
):
    label = uuid.uuid4().hex
    before = row_counts(signup_engine)
    after_events = []

    with signup_engine.connect() as connection:
        outer = connection.begin()
        factory = _external_bindings(signup_engine, connection)[binding]
        context, hooks = make_context(AccountsStore(session_factory=factory))
        hooks.register_after("user.create", after_events.append)
        hooks.register_after("social_account.create", after_events.append)

        with pytest.raises(RuntimeError, match="already in a transaction"):
            signup(context, label)

        assert outer.is_active
        outer.rollback()

    assert after_events == []
    assert row_counts(signup_engine) == before


def test_every_configured_model_binding_is_checked(signup_engine):
    with signup_engine.connect() as connection:
        outer = connection.begin()
        # Only the second model joins the application's transaction.
        store = AccountsStore(
            session_factory=lambda: Session(
                signup_engine, binds={SocialAccount: connection}
            )
        )

        with pytest.raises(RuntimeError, match="already in a transaction"):
            store.find_user_by_email(f"{uuid.uuid4().hex}@example.com")

        assert outer.is_active
        outer.rollback()


@pytest.mark.parametrize("binding", ["mapped", "routed"])
def test_session_store_bound_to_an_application_transaction_is_rejected(
    signup_engine, binding
):
    user_id = uuid.uuid4().hex
    hooks = HookRegistry()
    logins = []
    hooks.register_after("login", logins.append)

    with signup_engine.connect() as connection:
        outer = connection.begin()
        factory = {
            "mapped": lambda: Session(binds={UserSession: connection}),
            "routed": lambda: RoutedSession(signup_engine, connection),
        }[binding]

        with pytest.raises(RuntimeError, match="already in a transaction"):
            issue_bearer_session(
                user_id,
                hooks=hooks,
                session_storage=SessionStore(session_factory=factory),
                session_config=None,
            )

        assert outer.is_active
        outer.rollback()

    assert logins == []
    with Session(signup_engine) as session:
        assert (
            session.exec(
                select(UserSession).where(UserSession.user_id == user_id)
            ).all()
            == []
        )


def test_connection_without_a_transaction_is_supported(signup_engine):
    label = uuid.uuid4().hex
    after_events = []

    with signup_engine.connect() as connection:
        context, hooks = make_context(
            AccountsStore(
                session_factory=lambda: Session(
                    binds={User: connection, SocialAccount: connection}
                )
            )
        )
        hooks.register_after("user.create", lambda event: after_events.append("user"))

        signup(context, label)

        assert not connection.in_transaction()

    assert after_events == ["user"]
    with Session(signup_engine) as session:
        assert session.exec(
            select(User).where(User.email == f"{label}@example.com")
        ).one()
