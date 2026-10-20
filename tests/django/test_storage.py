from __future__ import annotations

import io
import time
import uuid
from datetime import timedelta

import pytest
import time_machine
from django.conf import settings
from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.core.management import call_command
from django.db import IntegrityError, transaction
from django.test import override_settings
from django.utils import timezone

from cross_auth._storage import (
    AccountsStorage,
    SecondaryStorage,
    SocialAccountCreate,
    User,
)
from cross_auth.django.models import ExpiringValue, SocialAccount
from cross_auth.django.storage import (
    DjangoAccountsStorage,
    DjangoSecondaryStorage,
    DjangoUser,
)
from cross_auth.exceptions import CrossAuthException
from tests.django.testapp.models import Profile

from .conftest import (
    CUSTOM_USER,
    connect,
    create_account,
    identity_data,
    make_user,
    run_in_threads,
    update_account,
)

pytestmark = pytest.mark.django_db


def _signup(
    storage: DjangoAccountsStorage,
    *,
    email: str = "person@example.com",
    provider_user_id: str = "google-sub-1",
) -> tuple[DjangoUser, SocialAccount]:
    return storage.create_user_with_identity(
        user={
            "user_info": {"id": provider_user_id, "email": email, "name": "Pat"},
            "email": email,
            "email_verified": True,
            "extra_fields": None,
        },
        identity=lambda user: identity_data(
            user.id, provider_user_id=provider_user_id, email=email
        ),
    )


def test_adapters_satisfy_core_protocols() -> None:
    accounts: AccountsStorage = DjangoAccountsStorage()
    secondary: SecondaryStorage = DjangoSecondaryStorage()
    assert accounts and secondary


def test_django_user_maps_native_values_conservatively() -> None:
    native = make_user("Person@Example.com", password="secret")
    user: User = DjangoUser(native, password_login=True)

    assert user.id == native.pk
    assert user.email == "Person@example.com"
    # Django has no verified-email flag; provider verification stays on the
    # identity and is never promoted to the user.
    assert user.email_verified is False
    assert user.hashed_password is None
    assert user.has_usable_password is True
    assert DjangoUser(native, password_login=False).has_usable_password is False

    native.set_unusable_password()
    assert DjangoUser(native, password_login=True).has_usable_password is False


def test_migrations_match_models() -> None:
    output = io.StringIO()
    call_command(
        "makemigrations", "cross_auth", check=True, dry_run=True, stdout=output
    )


@pytest.mark.django_db(transaction=True)
def test_migrates_an_existing_installation() -> None:
    call_command("migrate", "cross_auth", "zero", verbosity=0)
    existing = make_user("existing@example.com", password="secret")

    call_command("migrate", "cross_auth", verbosity=0)

    account = connect(existing)
    assert account.user == existing
    assert (
        get_user_model()._default_manager.get(pk=existing.pk).check_password("secret")
    )


def test_signup_creates_user_and_identity(storage: DjangoAccountsStorage) -> None:
    user, account = _signup(storage)

    native = get_user_model()._default_manager.get(pk=user.id)
    assert user.native == native
    assert native.get_username() == "person@example.com"
    assert not native.has_usable_password()
    assert account.user_id == native.pk
    assert (account.provider, account.provider_user_id) == ("google", "google-sub-1")
    assert account.provider_email_verified is True
    assert account.is_login_method is True
    # Provider credentials are not stored.
    assert account.access_token is None
    assert account.refresh_token is None
    if CUSTOM_USER:
        assert isinstance(native.pk, uuid.UUID)


@override_settings(CROSS_AUTH={"CREATE_USER": "tests.django.factories.with_profile"})
def test_signup_commits_factory_rows(storage: DjangoAccountsStorage) -> None:
    user, _ = _signup(storage)

    assert Profile.objects.get(user_id=user.id).display_name == "Pat"


@pytest.mark.django_db(transaction=True)
@override_settings(CROSS_AUTH={"CREATE_USER": "tests.django.factories.with_profile"})
def test_signup_rolls_back_user_and_factory_rows(
    storage: DjangoAccountsStorage,
) -> None:
    def failing_identity(user: User) -> SocialAccountCreate:
        raise RuntimeError("identity hook failed")

    with pytest.raises(RuntimeError, match="identity hook failed"):
        storage.create_user_with_identity(
            user={
                "user_info": {"name": "Pat"},
                "email": "person@example.com",
                "email_verified": True,
                "extra_fields": None,
            },
            identity=failing_identity,
        )

    assert not get_user_model()._default_manager.exists()
    assert not Profile.objects.exists()
    assert not SocialAccount.objects.exists()


@pytest.mark.django_db(transaction=True)
def test_signup_race_keeps_one_user(
    storage: DjangoAccountsStorage, is_postgres: bool
) -> None:
    def sign_up(index: int) -> DjangoUser:
        user, _ = _signup(storage, email=f"person{index}@example.com")
        return user

    results = run_in_threads(4, sign_up)

    winners = [result for result in results if isinstance(result, DjangoUser)]
    losers = [result for result in results if isinstance(result, CrossAuthException)]
    assert len(winners) == 1, results
    assert len(losers) == 3, results
    assert {loser.error for loser in losers} == {"account_already_linked"}
    assert get_user_model()._default_manager.count() == 1
    assert SocialAccount.objects.get().user_id == winners[0].id


@pytest.mark.django_db(transaction=True)
@override_settings(CROSS_AUTH={"CREATE_USER": "tests.django.factories.with_profile"})
def test_same_email_signup_race_is_a_conflict(storage: DjangoAccountsStorage) -> None:
    # Independent first sign-ins with one identity: every attempt saw no user
    # with this email, so each runs the factory and its unique native username
    # or email rejects all but one.
    results = run_in_threads(4, lambda _: _signup(storage)[0])

    winners = [result for result in results if isinstance(result, DjangoUser)]
    losers = [result for result in results if isinstance(result, CrossAuthException)]
    assert len(winners) == 1, results
    assert len(losers) == 3, results
    assert {loser.error for loser in losers} == {"account_not_linked"}
    native = get_user_model()._default_manager.get()
    assert native.pk == winners[0].id
    assert Profile.objects.get().user == native
    assert SocialAccount.objects.get().user_id == native.pk

    # Signing in again finds the identity the winner stored.
    account = storage.find_social_account(
        provider="google", provider_user_id="google-sub-1"
    )
    assert account is not None
    assert account.user_id == native.pk


@pytest.mark.django_db(transaction=True)
def test_same_email_signup_race_does_not_merge_identities(
    storage: DjangoAccountsStorage,
) -> None:
    identities = [("google", "google-sub-1"), ("github", "github-id-1")]

    def sign_up(index: int) -> DjangoUser:
        provider, provider_user_id = identities[index]
        user, _ = storage.create_user_with_identity(
            user={
                "user_info": {"name": "Pat"},
                "email": "person@example.com",
                "email_verified": True,
                "extra_fields": None,
            },
            identity=lambda created: identity_data(
                created.id, provider=provider, provider_user_id=provider_user_id
            ),
        )
        return user

    results = run_in_threads(2, sign_up)

    winners = [result for result in results if isinstance(result, DjangoUser)]
    losers = [result for result in results if isinstance(result, CrossAuthException)]
    assert len(winners) == 1, results
    assert [loser.error for loser in losers] == ["account_not_linked"], results
    # The losing identity is not attached to the winner's account.
    account = SocialAccount.objects.get()
    assert account.user_id == winners[0].id
    assert get_user_model()._default_manager.count() == 1


@pytest.mark.django_db(transaction=True)
@override_settings(
    CROSS_AUTH={"CREATE_USER": "tests.django.factories.with_duplicate_profile"}
)
def test_unrelated_factory_integrity_errors_propagate(
    storage: DjangoAccountsStorage,
) -> None:
    with pytest.raises(IntegrityError):
        _signup(storage)

    assert not get_user_model()._default_manager.exists()
    assert not Profile.objects.exists()
    assert not SocialAccount.objects.exists()

    # A later sign-in with a working factory still succeeds.
    with override_settings(
        CROSS_AUTH={"CREATE_USER": "tests.django.factories.with_profile"}
    ):
        user, account = _signup(storage)
    assert account.user_id == user.id


def test_signup_with_unmanaged_default_factory_is_rejected(
    storage: DjangoAccountsStorage,
) -> None:
    if not CUSTOM_USER:
        pytest.skip("Django's user model uses UserManager")

    with override_settings(CROSS_AUTH={}):
        with pytest.raises(ImproperlyConfigured, match="CREATE_USER"):
            _signup(storage)


@pytest.mark.django_db(transaction=True)
def test_on_commit_follows_the_outermost_transaction(
    storage: DjangoAccountsStorage,
) -> None:
    calls: list[str] = []

    storage.on_commit(lambda: calls.append("autocommit"))
    assert calls == ["autocommit"]

    with transaction.atomic():
        _signup(storage)
        storage.on_commit(lambda: calls.append("outer"))
        with transaction.atomic():
            storage.on_commit(lambda: calls.append("savepoint"))
        assert calls == ["autocommit"]
    assert calls == ["autocommit", "outer", "savepoint"]


@pytest.mark.django_db(transaction=True)
def test_rolled_back_writes_drop_their_callbacks(
    storage: DjangoAccountsStorage,
) -> None:
    calls: list[str] = []

    with pytest.raises(RuntimeError):
        with transaction.atomic():
            _signup(storage)
            storage.on_commit(lambda: calls.append("outer"))
            raise RuntimeError("rollback")

    with transaction.atomic():
        try:
            with transaction.atomic():
                _signup(storage, provider_user_id="google-sub-2")
                storage.on_commit(lambda: calls.append("savepoint"))
                raise RuntimeError("roll back the savepoint")
        except RuntimeError:
            pass
        storage.on_commit(lambda: calls.append("outer kept"))

    assert calls == ["outer kept"]
    assert not SocialAccount.objects.exists()
    assert not get_user_model()._default_manager.exists()


def test_find_user_by_email_matches_case_insensitively(
    storage: DjangoAccountsStorage,
) -> None:
    native = make_user("Person@Example.com")

    found = storage.find_user_by_email("person@example.com")

    assert found is not None
    assert found.native == native
    assert storage.find_user_by_email("other@example.com") is None


def test_find_user_by_email_rejects_ambiguous_matches(
    storage: DjangoAccountsStorage,
) -> None:
    if CUSTOM_USER:
        pytest.skip("The custom user model has unique emails")
    make_user("person@example.com")
    from django.contrib.auth.models import User

    User.objects.create_user("second", email="PERSON@example.com")

    with pytest.raises(CrossAuthException) as error:
        storage.find_user_by_email("person@example.com")
    assert error.value.error == "account_not_linked"


@pytest.mark.parametrize("value", ["not-an-id", "", "1; drop table"])
def test_invalid_ids_do_not_match(
    storage: DjangoAccountsStorage, value: object
) -> None:
    connect(make_user("person@example.com"))

    assert storage.find_user_by_id(value) is None
    assert storage.find_social_account_by_id(value) is None
    assert storage.list_social_accounts(user_id=value) == []
    assert (
        storage.find_social_account(
            provider="google", provider_user_id="google-sub-1", user_id=value
        )
        is None
    )
    assert (
        storage.disconnect_social_account(
            user_id=value, provider="google", social_account_id=value
        )
        == "not_found"
    )


def test_find_social_account_filters(storage: DjangoAccountsStorage) -> None:
    owner = make_user("owner@example.com")
    account = connect(owner, is_login_method=False)

    assert storage.find_social_account(
        provider="google", provider_user_id="google-sub-1"
    ) == (account)
    assert (
        storage.find_social_account(
            provider="google", provider_user_id="google-sub-1", is_login_method=True
        )
        is None
    )
    assert (
        storage.find_social_account(
            provider="google",
            provider_user_id="google-sub-1",
            user_id=make_user("other@example.com").pk,
        )
        is None
    )
    assert storage.has_social_account(
        provider="google", provider_user_id="google-sub-1"
    )
    assert storage.find_social_account_by_id(str(account.pk)) == account
    assert storage.list_social_accounts(user_id=str(owner.pk)) == [account]


def test_identity_has_one_owner(storage: DjangoAccountsStorage) -> None:
    owner = make_user("owner@example.com")
    other = make_user("other@example.com")
    connect(owner)

    with pytest.raises(CrossAuthException) as error:
        create_account(storage, identity_data(other.pk))
    assert error.value.error == "account_already_linked"
    assert SocialAccount.objects.get().user_id == owner.pk


def test_same_owner_retry_returns_existing_row(storage: DjangoAccountsStorage) -> None:
    owner = make_user("owner@example.com")
    existing = connect(owner)

    retried = create_account(
        storage, identity_data(owner.pk, email="changed@example.com")
    )

    assert retried.pk == existing.pk
    assert retried.provider_email == "person@example.com"


def test_create_cannot_promote_a_connection(storage: DjangoAccountsStorage) -> None:
    owner = make_user("owner@example.com")
    connect(owner, is_login_method=False)

    with pytest.raises(CrossAuthException) as error:
        create_account(storage, identity_data(owner.pk, is_login_method=True))
    assert error.value.error == "account_already_linked"
    assert SocialAccount.objects.get().is_login_method is False


def test_update_promotes_but_never_demotes(storage: DjangoAccountsStorage) -> None:
    account = connect(make_user("owner@example.com"), is_login_method=False)

    updated = update_account(storage, account)
    assert updated.is_login_method is False
    assert updated.provider_email == "new@example.com"

    assert update_account(storage, account, enable_login=True).is_login_method
    assert update_account(storage, account, enable_login=False).is_login_method
    assert SocialAccount.objects.get().is_login_method is True


def test_hook_extra_fields_are_rejected(storage: DjangoAccountsStorage) -> None:
    owner = make_user("owner@example.com")

    data = identity_data(owner.pk)
    data["extra_fields"] = {"team": "a"}

    with pytest.raises(TypeError, match="no extra fields"):
        create_account(storage, data)


class TestDisconnect:
    def test_rejects_other_users_and_providers(
        self, storage: DjangoAccountsStorage
    ) -> None:
        owner = make_user("owner@example.com", password="secret")
        other = make_user("other@example.com", password="secret")
        account = connect(owner)

        for user_id, provider in [(other.pk, "google"), (owner.pk, "github")]:
            assert (
                storage.disconnect_social_account(
                    user_id=user_id, provider=provider, social_account_id=account.pk
                )
                == "not_found"
            )
        assert SocialAccount.objects.filter(pk=account.pk).exists()

    def test_keeps_the_last_login_method(self, storage: DjangoAccountsStorage) -> None:
        owner = make_user("owner@example.com")
        account = connect(owner)

        assert (
            storage.disconnect_social_account(
                user_id=owner.pk, provider="google", social_account_id=account.pk
            )
            == "last_login_method"
        )
        assert SocialAccount.objects.filter(pk=account.pk).exists()

    def test_usable_password_is_an_alternative(
        self, storage: DjangoAccountsStorage
    ) -> None:
        owner = make_user("owner@example.com", password="secret")
        account = connect(owner)

        assert (
            storage.disconnect_social_account(
                user_id=owner.pk, provider="google", social_account_id=account.pk
            )
            == "disconnected"
        )
        assert not SocialAccount.objects.exists()

    def test_password_is_ignored_without_password_login(
        self, storage: DjangoAccountsStorage
    ) -> None:
        owner = make_user("owner@example.com", password="secret")
        account = connect(owner)

        with override_settings(
            CROSS_AUTH={**getattr(settings, "CROSS_AUTH", {}), "PASSWORD_LOGIN": False}
        ):
            result = storage.disconnect_social_account(
                user_id=owner.pk, provider="google", social_account_id=account.pk
            )
        assert result == "last_login_method"

    def test_another_login_identity_is_an_alternative(
        self, storage: DjangoAccountsStorage
    ) -> None:
        owner = make_user("owner@example.com")
        account = connect(owner)
        connect(owner, provider_user_id="google-sub-2")

        assert (
            storage.disconnect_social_account(
                user_id=str(owner.pk), provider="google", social_account_id=account.pk
            )
            == "disconnected"
        )

    def test_connection_only_identity_is_never_required(
        self, storage: DjangoAccountsStorage
    ) -> None:
        owner = make_user("owner@example.com")
        connect(owner)
        connection = connect(
            owner, provider_user_id="google-sub-2", is_login_method=False
        )

        assert (
            storage.disconnect_social_account(
                user_id=owner.pk, provider="google", social_account_id=connection.pk
            )
            == "disconnected"
        )

    @pytest.mark.django_db(transaction=True)
    def test_concurrent_disconnects_keep_one_login_method(
        self, storage: DjangoAccountsStorage, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        owner = make_user("owner@example.com")
        accounts = [
            connect(owner, provider_user_id=f"google-sub-{index}") for index in range(2)
        ]
        # Widen the gap between reading the alternatives and deleting, so
        # unserialized removals would both see the other identity.
        wrap = storage._wrap

        def slow_wrap(native: AbstractBaseUser) -> DjangoUser:
            time.sleep(0.3)
            return wrap(native)

        monkeypatch.setattr(storage, "_wrap", slow_wrap)

        results = run_in_threads(
            2,
            lambda index: storage.disconnect_social_account(
                user_id=owner.pk,
                provider="google",
                social_account_id=accounts[index].pk,
            ),
        )

        assert sorted(map(str, results)) == ["disconnected", "last_login_method"]
        assert SocialAccount.objects.filter(user=owner).count() == 1


class TestSecondaryStorage:
    def test_set_get_delete(self, secondary: DjangoSecondaryStorage) -> None:
        secondary.set("key", "one", ttl=60)
        secondary.set("key", "two", ttl=60)
        assert secondary.get("key") == "two"

        secondary.delete("key")
        assert secondary.get("key") is None
        secondary.delete("key")

    def test_values_expire(self, secondary: DjangoSecondaryStorage) -> None:
        with time_machine.travel(timezone.now(), tick=False) as clock:
            secondary.set("short", "value", ttl=10)
            secondary.set("forever", "value")
            clock.shift(timedelta(seconds=11))

            assert secondary.get("short") is None
            assert secondary.pop("short") is None
            assert secondary.get("forever") == "value"

            secondary.set("other", "value", ttl=10)
        assert not ExpiringValue.objects.filter(key="short").exists()

    def test_pop_returns_a_value_once(self, secondary: DjangoSecondaryStorage) -> None:
        secondary.set("state", "value", ttl=60)

        assert secondary.pop("state") == "value"
        assert secondary.pop("state") is None
        assert secondary.pop("missing") is None

    @pytest.mark.django_db(transaction=True)
    def test_concurrent_pops_have_one_winner(
        self, secondary: DjangoSecondaryStorage
    ) -> None:
        for attempt in range(5):
            secondary.set(f"state-{attempt}", "value", ttl=60)
            results = run_in_threads(
                4, lambda index, attempt=attempt: secondary.pop(f"state-{attempt}")
            )
            assert results.count("value") == 1, results
            assert results.count(None) == 3, results
