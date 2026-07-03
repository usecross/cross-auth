from datetime import datetime, timedelta, timezone

import pytest
from sqlmodel import Session

from cross_auth.exceptions import CrossAuthException
from cross_auth.storage.sqlmodel import SQLModelAccountsStorage

from .models import (
    AccountsStore,
    LeanAccountsStore,
    LeanSocialAccount,
    PropAccountsStore,
    PropertyScopeSocialAccount,
    SocialAccount,
    SoftDeleteAccountsStore,
    User,
)

NOW = datetime(2026, 6, 6, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def store(engine):
    return AccountsStore(session_factory=lambda: Session(engine))


def _seed_user(
    engine,
    *,
    email: str = "a@example.com",
    email_verified: bool = True,
    hashed_password: str | None = None,
    deleted: bool = False,
) -> int:
    with Session(engine) as session:
        user = User(
            email=email,
            email_verified=email_verified,
            hashed_password=hashed_password,
            deleted=deleted,
        )
        session.add(user)
        session.commit()
        user_id = user.id
    assert user_id is not None
    return user_id


def _seed_social(
    engine, *, user_id, provider="github", provider_user_id="123", **kwargs
):
    with Session(engine) as session:
        account = SocialAccount(
            user_id=user_id,
            provider=provider,
            provider_user_id=provider_user_id,
            **kwargs,
        )
        session.add(account)
        session.commit()
        return account.id


def test_find_user_by_email(store, engine):
    _seed_user(engine, email="found@example.com")

    user = store.find_user_by_email("found@example.com")

    assert user is not None
    assert user.email == "found@example.com"


def test_find_user_by_email_missing(store):
    assert store.find_user_by_email("nope@example.com") is None


def test_find_user_by_id(store, engine):
    user_id = _seed_user(engine)

    user = store.find_user_by_id(user_id)

    assert user is not None
    assert user.id == user_id


def test_find_user_by_id_coerces_string_ids(store, engine):
    # Session records store user ids as strings; the lookup must still match
    # an int primary key (and uncastable ids must answer None, not crash).
    user_id = _seed_user(engine)

    assert store.find_user_by_id(str(user_id)) is not None
    assert store.find_user_by_id("abc") is None


def test_returned_user_scalars_readable_after_close(store, engine):
    _seed_user(engine, email="x@example.com", hashed_password="hash")

    user = store.find_user_by_email("x@example.com")

    # No active session here; these must not trigger a DB hit.
    assert user.email == "x@example.com"
    assert user.email_verified is True
    assert user.has_usable_password is True


def test_returned_user_relationship_readable_after_close(store, engine):
    user_id = _seed_user(engine)
    _seed_social(engine, user_id=user_id, provider="github", provider_user_id="g1")

    user = store.find_user_by_id(user_id)

    # social_accounts is eager-loaded, so this works after the session closed.
    accounts = list(user.social_accounts)
    assert len(accounts) == 1
    assert accounts[0].provider == "github"


def test_user_model_with_property_social_accounts(engine):
    # The User protocol allows social_accounts to be a plain property; the
    # adapter must not assume a mapped relationship of that name.
    store = PropAccountsStore(session_factory=lambda: Session(engine))
    user = store.create_user(
        user_info={}, email="prop@example.com", email_verified=True
    )

    assert user.id is not None
    found = store.find_user_by_email("prop@example.com")
    assert found is not None
    assert list(found.social_accounts) == []


def test_soft_delete_hook_excludes_user(engine):
    _seed_user(engine, email="gone@example.com", deleted=True)
    store = SoftDeleteAccountsStore(session_factory=lambda: Session(engine))

    assert store.find_user_by_email("gone@example.com") is None


def test_create_user_bypasses_filter_user_query(engine):
    # A fresh user must always be returned, even when filter_user_query would
    # exclude it — otherwise create_user could return None mid-signup.
    class DeletedOnSignupStore(SoftDeleteAccountsStore):
        def on_signup(self, *, session, user, user_info, email_verified):
            user.deleted = True

    store = DeletedOnSignupStore(session_factory=lambda: Session(engine))

    user = store.create_user(
        user_info={}, email="soft@example.com", email_verified=True
    )

    assert user.id is not None
    assert list(user.social_accounts) == []
    assert store.find_user_by_id(user.id) is None  # filtered lookup excludes it


def test_on_signup_joins_the_create_user_transaction(engine):
    # The cloud-style signup: on_signup adds related rows to the session it
    # receives, and everything commits as one unit of work. The returned user
    # must still satisfy the read-after-close contract, including the
    # eager-loaded relationship rows created in the same transaction.
    class TeamSignupStore(AccountsStore):
        def on_signup(self, *, session, user, user_info, email_verified):
            # user_id is populated from the relationship at flush time.
            session.add(
                SocialAccount(  # ty: ignore[missing-argument]
                    user=user, provider="github", provider_user_id="linked-1"
                )
            )

    store = TeamSignupStore(session_factory=lambda: Session(engine))

    user = store.create_user(
        user_info={}, email="team@example.com", email_verified=True
    )

    # No open session here; both reads must not hit the database.
    assert user.email == "team@example.com"
    accounts = list(user.social_accounts)
    assert [a.provider_user_id for a in accounts] == ["linked-1"]


def test_on_signup_raise_aborts_the_signup(engine):
    # An invite check raising inside the hook rolls back the transaction:
    # neither the user nor any related rows are persisted.
    class InviteOnlyStore(AccountsStore):
        def on_signup(self, *, session, user, user_info, email_verified):
            session.add(
                SocialAccount(  # ty: ignore[missing-argument]
                    user=user, provider="github", provider_user_id="rollback-1"
                )
            )
            raise CrossAuthException("signup_not_allowed", "Invite only")

    store = InviteOnlyStore(session_factory=lambda: Session(engine))

    with pytest.raises(CrossAuthException):
        store.create_user(
            user_info={}, email="uninvited@example.com", email_verified=True
        )

    assert store.find_user_by_email("uninvited@example.com") is None
    assert (
        store.find_social_account(provider="github", provider_user_id="rollback-1")
        is None
    )


def test_build_user_controls_construction(engine):
    # Models needing more than UserModel(email=..., email_verified=...) —
    # generated usernames, renamed columns — override build_user.
    class CustomConstructionStore(SQLModelAccountsStorage[User, SocialAccount]):
        UserModel = User
        SocialAccountModel = SocialAccount

        def build_user(self, *, session, user_info, email, email_verified):
            return User(
                email=email,
                email_verified=email_verified,
                hashed_password=f"gen:{user_info['seed']}",
            )

    store = CustomConstructionStore(session_factory=lambda: Session(engine))

    user = store.create_user(
        user_info={"seed": "abc"}, email="built@example.com", email_verified=True
    )

    assert user.hashed_password == "gen:abc"
    assert user.email_verified is True


def test_on_signup_receives_email_verified(engine):
    captured = []

    class VerifiedStore(AccountsStore):
        def on_signup(self, *, session, user, user_info, email_verified):
            captured.append(email_verified)

    store = VerifiedStore(session_factory=lambda: Session(engine))
    store.create_user(user_info={}, email="v@example.com", email_verified=True)

    assert captured == [True]


def test_after_signup_runs_after_commit(engine):
    seen = []

    class TelemetryStore(AccountsStore):
        def after_signup(self, *, user, user_info):
            # The transaction is already committed: the user has its id and
            # is visible to a fresh session.
            found = self.find_user_by_id(user.id)
            seen.append((user.id, found is not None))

    store = TelemetryStore(session_factory=lambda: Session(engine))

    user = store.create_user(
        user_info={}, email="telemetry@example.com", email_verified=True
    )

    assert seen == [(user.id, True)]


def test_find_social_account(store, engine):
    user_id = _seed_user(engine)
    _seed_social(engine, user_id=user_id, provider="github", provider_user_id="g1")

    account = store.find_social_account(provider="github", provider_user_id="g1")

    assert account is not None
    assert account.provider_user_id == "g1"


def test_find_social_account_missing(store):
    assert store.find_social_account(provider="x", provider_user_id="y") is None


def test_find_social_account_by_id(store, engine):
    user_id = _seed_user(engine)
    account_id = _seed_social(engine, user_id=user_id)

    account = store.find_social_account_by_id(account_id)

    assert account is not None
    assert account.id == account_id


def test_find_social_account_by_id_coerces_string_ids(store, engine):
    user_id = _seed_user(engine)
    account_id = _seed_social(engine, user_id=user_id)

    assert store.find_social_account_by_id(str(account_id)) is not None
    assert store.find_social_account_by_id("abc") is None


def test_list_social_accounts(store, engine):
    user_id = _seed_user(engine)
    _seed_social(engine, user_id=user_id, provider_user_id="a")
    _seed_social(engine, user_id=user_id, provider_user_id="b")

    accounts = store.list_social_accounts(user_id=user_id)

    assert len(accounts) == 2


def test_create_social_account(store, engine):
    user_id = _seed_user(engine)

    account = store.create_social_account(
        user_id=user_id,
        provider="google",
        provider_user_id="g-1",
        access_token="at",
        refresh_token="rt",
        access_token_expires_at=None,
        refresh_token_expires_at=None,
        scope="email",
        user_info={"foo": "bar"},
        provider_email="g@example.com",
        provider_email_verified=True,
        is_login_method=True,
    )

    assert account.id is not None
    assert account.provider == "google"
    assert account.access_token == "at"
    assert store.find_social_account_by_id(account.id) is not None


def test_social_account_token_expiry_roundtrips_aware(store, engine):
    user_id = _seed_user(engine)
    expires = NOW + timedelta(hours=1)

    account = store.create_social_account(
        user_id=user_id,
        provider="google",
        provider_user_id="g-1",
        access_token="at",
        refresh_token=None,
        access_token_expires_at=expires,
        refresh_token_expires_at=None,
        scope=None,
        user_info={},
        provider_email=None,
        provider_email_verified=None,
        is_login_method=True,
    )

    fetched = store.find_social_account_by_id(account.id)
    # Stored as UTC and read back timezone-aware, so the core can compare it
    # against aware "now" values without a TypeError.
    assert fetched.access_token_expires_at == expires
    assert fetched.access_token_expires_at.tzinfo is not None


def test_update_social_account(store, engine):
    user_id = _seed_user(engine)
    account_id = _seed_social(engine, user_id=user_id, access_token="old")

    updated = store.update_social_account(
        account_id,
        access_token="new",
        refresh_token="rt2",
        access_token_expires_at=None,
        refresh_token_expires_at=None,
        scope="profile",
        user_info={},
        provider_email="new@example.com",
        provider_email_verified=False,
    )

    assert updated.access_token == "new"
    assert updated.scope == "profile"

    # Re-read through a fresh session: the rotated token must have been
    # committed, not just applied to the in-memory row update_social_account
    # returned.
    persisted = store.find_social_account_by_id(account_id)
    assert persisted is not None
    assert persisted.access_token == "new"
    assert persisted.scope == "profile"


def test_update_missing_social_account_raises(store):
    with pytest.raises(ValueError):
        store.update_social_account(
            99999,
            access_token=None,
            refresh_token=None,
            access_token_expires_at=None,
            refresh_token_expires_at=None,
            scope=None,
            user_info={},
            provider_email=None,
            provider_email_verified=None,
        )


def test_delete_social_account(store, engine):
    user_id = _seed_user(engine)
    account_id = _seed_social(engine, user_id=user_id)

    store.delete_social_account(account_id)

    assert store.find_social_account_by_id(account_id) is None


def test_delete_missing_social_account_is_noop(store):
    store.delete_social_account(99999)  # should not raise
    store.delete_social_account("abc")  # uncastable id: also a no-op


def test_filter_hook_applies_to_writes(store, engine):
    # A scoped store must not update or delete rows its finds would never
    # return.
    class GithubOnlyStore(AccountsStore):
        def filter_social_account_query(self, statement):
            return statement.where(SocialAccount.provider == "github")

    scoped = GithubOnlyStore(session_factory=lambda: Session(engine))
    user_id = _seed_user(engine)
    account_id = _seed_social(engine, user_id=user_id, provider="google")

    scoped.delete_social_account(account_id)  # out of scope: no-op
    assert store.find_social_account_by_id(account_id) is not None

    with pytest.raises(ValueError):
        scoped.update_social_account(
            account_id,
            access_token=None,
            refresh_token=None,
            access_token_expires_at=None,
            refresh_token_expires_at=None,
            scope=None,
            user_info={},
            provider_email=None,
            provider_email_verified=None,
        )


def test_create_user_override(store):
    user = store.create_user(
        user_info={"hashed_password": "hashed"},
        email="new@example.com",
        email_verified=False,
    )

    assert user.id is not None
    assert user.email == "new@example.com"
    assert user.has_usable_password is True
    assert list(user.social_accounts) == []


def test_direct_instantiation_with_default_create_user(engine):
    # No subclass needed: models go to the constructor and the default
    # create_user works out of the box.
    store = SQLModelAccountsStorage(
        User, SocialAccount, session_factory=lambda: Session(engine)
    )

    user = store.create_user(
        user_info={}, email="direct@example.com", email_verified=True
    )

    assert user.id is not None
    assert user.email == "direct@example.com"
    assert list(user.social_accounts) == []
    assert store.find_user_by_email("direct@example.com") is not None


def test_missing_model_declaration_raises_at_construction(engine):
    with pytest.raises(TypeError, match="UserModel"):
        SQLModelAccountsStorage(session_factory=lambda: Session(engine))


def test_model_missing_required_field_raises_at_construction(engine):
    class NotAUser:
        id = None  # declares id but no email

    class BadStore(AccountsStore):
        UserModel = NotAUser

    with pytest.raises(TypeError, match="email"):
        BadStore(session_factory=lambda: Session(engine))


def test_user_model_missing_protocol_property_raises_at_construction(engine):
    # Core reads has_usable_password mid-flow (account linking); a model
    # without it must fail at startup, not during an OAuth login.
    class BareUser:
        id = None
        email = None
        email_verified = None
        hashed_password = None
        social_accounts = None

    class BadStore(AccountsStore):
        UserModel = BareUser

    with pytest.raises(TypeError, match="has_usable_password"):
        BadStore(session_factory=lambda: Session(engine))


def test_social_account_model_missing_protocol_field_raises_at_construction(engine):
    class BareSocialAccount:
        id = None
        user_id = None
        provider = None
        provider_user_id = None
        # missing provider_email, provider_email_verified, is_login_method

    class BadStore(AccountsStore):
        SocialAccountModel = BareSocialAccount

    with pytest.raises(TypeError, match="provider_email"):
        BadStore(session_factory=lambda: Session(engine))


def test_missing_token_columns_with_default_builders_raises_at_construction(engine):
    # SQLModel silently ignores unknown constructor kwargs, so a model missing
    # the token columns would silently drop OAuth tokens. With the default
    # payload builders this must fail at startup.
    class BadStore(AccountsStore):
        SocialAccountModel = LeanSocialAccount

    with pytest.raises(TypeError, match="access_token"):
        BadStore(session_factory=lambda: Session(engine))


def test_write_field_as_property_raises_at_construction(engine):
    # `scope` is a read-only property on this model, not a mapped column.
    # hasattr(model, "scope") is True, but SQLModel's constructor silently
    # drops it (it only accepts pydantic fields) — construction must fail
    # instead of quietly losing the OAuth scope on every write.
    class BadStore(AccountsStore):
        SocialAccountModel = PropertyScopeSocialAccount

    with pytest.raises(TypeError, match="scope"):
        BadStore(session_factory=lambda: Session(engine))


def test_tokenless_model_works_with_overridden_builders(engine):
    store = LeanAccountsStore(session_factory=lambda: Session(engine))
    user_id = _seed_user(engine)

    account = store.create_social_account(
        user_id=user_id,
        provider="google",
        provider_user_id="g-1",
        access_token="secret",
        refresh_token=None,
        access_token_expires_at=None,
        refresh_token_expires_at=None,
        scope="email",
        user_info={},
        provider_email="a@example.com",
        provider_email_verified=True,
        is_login_method=True,
    )

    assert account.provider == "google"
    assert account.provider_email == "a@example.com"
    assert getattr(account, "access_token", None) is None

    updated = store.update_social_account(
        account.id,
        access_token="rotated",
        refresh_token=None,
        access_token_expires_at=None,
        refresh_token_expires_at=None,
        scope="email",
        user_info={},
        provider_email="b@example.com",
        provider_email_verified=True,
    )

    assert updated.provider_email == "b@example.com"


def test_payload_builder_typo_raises_at_write(engine):
    class TypoStore(AccountsStore):
        def build_social_account_create_values(self, *, user_info, **fields):
            fields["acess_token"] = fields.pop("access_token")
            return fields

    store = TypoStore(session_factory=lambda: Session(engine))
    user_id = _seed_user(engine)

    with pytest.raises(TypeError, match="acess_token"):
        store.create_social_account(
            user_id=user_id,
            provider="google",
            provider_user_id="g-1",
            access_token="secret",
            refresh_token=None,
            access_token_expires_at=None,
            refresh_token_expires_at=None,
            scope=None,
            user_info={},
            provider_email=None,
            provider_email_verified=None,
            is_login_method=True,
        )


def test_payload_builder_hook(engine):
    class CustomStore(AccountsStore):
        def build_social_account_create_values(self, *, user_info, **fields):
            fields["scope"] = f"derived:{user_info.get('login')}"
            return fields

    store = CustomStore(session_factory=lambda: Session(engine))
    user_id = _seed_user(engine)

    account = store.create_social_account(
        user_id=user_id,
        provider="google",
        provider_user_id="g-1",
        access_token=None,
        refresh_token=None,
        access_token_expires_at=None,
        refresh_token_expires_at=None,
        scope="ignored",
        user_info={"login": "octocat"},
        provider_email=None,
        provider_email_verified=None,
        is_login_method=True,
    )

    assert account.scope == "derived:octocat"


def test_update_payload_builder_hook(engine):
    class CustomStore(AccountsStore):
        def build_social_account_update_values(self, *, user_info, record, **fields):
            fields["scope"] = f"derived:{user_info.get('login')}"
            return fields

    store = CustomStore(session_factory=lambda: Session(engine))
    user_id = _seed_user(engine)
    account_id = _seed_social(engine, user_id=user_id, access_token="old")

    updated = store.update_social_account(
        account_id,
        access_token="new",
        refresh_token=None,
        access_token_expires_at=None,
        refresh_token_expires_at=None,
        scope="ignored",
        user_info={"login": "octocat"},
        provider_email=None,
        provider_email_verified=None,
    )

    assert updated.scope == "derived:octocat"
    assert updated.access_token == "new"


def test_update_payload_builder_receives_the_existing_record(engine):
    # The cloud case: provider_username is recomputed on update from the
    # row's provider and provider_user_id, which are not among the update
    # fields — the hook must be able to read them from the loaded record.
    class CustomStore(AccountsStore):
        def build_social_account_update_values(self, *, user_info, record, **fields):
            fields["scope"] = f"{record.provider}:{record.provider_user_id}"
            return fields

    store = CustomStore(session_factory=lambda: Session(engine))
    user_id = _seed_user(engine)
    account_id = _seed_social(
        engine, user_id=user_id, provider="github", provider_user_id="g-7"
    )

    updated = store.update_social_account(
        account_id,
        access_token=None,
        refresh_token=None,
        access_token_expires_at=None,
        refresh_token_expires_at=None,
        scope=None,
        user_info={},
        provider_email=None,
        provider_email_verified=None,
    )

    assert updated.scope == "github:g-7"
