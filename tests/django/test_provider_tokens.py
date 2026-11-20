"""Keeping providers' tokens, encrypted, with CROSS_AUTH["PROVIDER_TOKENS"]."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from django.conf import settings
from django.core import checks
from django.test import Client, override_settings
from django.utils import timezone

from cross_auth.django.checks import check_settings
from cross_auth.django.models import SocialAccount
from cross_auth.django.storage import DjangoAccountsStorage

from .fake_google import FakeGoogle
from .support import (
    create_account,
    csrf_post,
    identity_data,
    make_user,
    sign_in,
)

pytestmark = pytest.mark.django_db

TOKENS = {
    "encrypt": "tests.django.token_crypto.encrypt",
    "decrypt": "tests.django.token_crypto.decrypt",
}


def keeping_tokens(**extra: Any) -> Any:
    return override_settings(
        CROSS_AUTH={**settings.CROSS_AUTH, "PROVIDER_TOKENS": TOKENS, **extra}
    )


def update(storage: DjangoAccountsStorage, account: SocialAccount, **fields: Any):
    values: dict[str, Any] = {
        "access_token": "new-access",
        "refresh_token": "new-refresh",
        "access_token_expires_at": None,
        "refresh_token_expires_at": None,
        "scope": "repo",
        **fields,
    }
    return storage.update_social_account(
        account.pk,
        **values,
        user_info={},
        provider_email="person@example.com",
        provider_email_verified=True,
    )


# Storage


def test_tokens_are_not_stored_by_default() -> None:
    storage = DjangoAccountsStorage()
    account = create_account(storage, identity_data(make_user("p@example.com").pk))

    row = SocialAccount.objects.get(pk=account.pk)
    assert row.encrypted_access_token is None
    assert row.encrypted_refresh_token is None
    assert row.scope is None
    assert row.access_token is None
    assert row.refresh_token is None


@keeping_tokens()
def test_tokens_are_stored_encrypted_and_read_back() -> None:
    storage = DjangoAccountsStorage()
    data = identity_data(make_user("p@example.com").pk)
    expires = timezone.now() + timedelta(hours=8)
    data["access_token_expires_at"] = expires

    account = create_account(storage, data)

    row = SocialAccount.objects.get(pk=account.pk)
    # Stored as the application's encrypt function returned them.
    assert row.encrypted_access_token == "enc:ssecca"
    assert row.encrypted_refresh_token == "enc:hserfer"
    assert row.access_token == "access"
    assert row.refresh_token == "refresh"
    assert row.access_token_expires_at == expires
    assert row.scope == "openid email profile"


@keeping_tokens()
def test_an_update_replaces_the_tokens() -> None:
    storage = DjangoAccountsStorage()
    account = create_account(storage, identity_data(make_user("p@example.com").pk))

    updated = update(storage, account)

    assert updated.access_token == "new-access"
    assert updated.refresh_token == "new-refresh"
    assert updated.scope == "repo"


@keeping_tokens()
def test_a_sign_in_without_a_refresh_token_clears_the_old_one() -> None:
    storage = DjangoAccountsStorage()
    account = create_account(storage, identity_data(make_user("p@example.com").pk))

    updated = update(storage, account, refresh_token=None)

    # Stored values follow what core hands over; core keeps old ones itself
    # when it means to.
    assert updated.refresh_token is None
    assert updated.encrypted_refresh_token is None


def test_turning_the_setting_off_clears_tokens_on_the_next_write() -> None:
    storage = DjangoAccountsStorage()
    with keeping_tokens():
        account = create_account(storage, identity_data(make_user("p@example.com").pk))
        assert SocialAccount.objects.get().encrypted_access_token

    update(storage, account)

    row = SocialAccount.objects.get()
    assert row.encrypted_access_token is None
    assert row.encrypted_refresh_token is None
    assert row.scope is None


@keeping_tokens()
def test_a_token_that_cannot_be_decrypted_counts_as_missing() -> None:
    storage = DjangoAccountsStorage()
    account = create_account(storage, identity_data(make_user("p@example.com").pk))
    SocialAccount.objects.update(encrypted_access_token="written-with-an-old-key")

    assert SocialAccount.objects.get(pk=account.pk).access_token is None


@keeping_tokens()
def test_signup_stores_the_tokens() -> None:
    storage = DjangoAccountsStorage()
    _, account = storage.create_user_with_identity(
        user={
            "user_info": {"id": "google-sub-1", "email": "p@example.com"},
            "email": "p@example.com",
            "email_verified": True,
            "extra_fields": None,
        },
        identity=lambda user: identity_data(user.id, email="p@example.com"),
    )

    assert SocialAccount.objects.get(pk=account.pk).access_token == "access"


# Through the views


@pytest.mark.django_db(transaction=True)
@keeping_tokens()
def test_sign_in_keeps_the_provider_token(client: Client, google: FakeGoogle) -> None:
    before = timezone.now()

    sign_in(client, google)

    row = SocialAccount.objects.get()
    assert row.access_token == "google-access-token"
    assert row.encrypted_access_token != "google-access-token"
    assert row.scope == "openid email profile"
    assert row.access_token_expires_at is not None
    assert (
        before + timedelta(seconds=3590)
        < row.access_token_expires_at
        < timezone.now() + timedelta(seconds=3610)
    )


@pytest.mark.django_db(transaction=True)
@keeping_tokens()
def test_a_returning_sign_in_replaces_the_token(
    client: Client, google: FakeGoogle
) -> None:
    sign_in(client, google)
    SocialAccount.objects.update(encrypted_access_token="enc:elats")
    csrf_post(client, "/accounts/logout/")

    sign_in(client, google)

    assert SocialAccount.objects.get().access_token == "google-access-token"


@pytest.mark.django_db(transaction=True)
@keeping_tokens()
def test_linking_again_refreshes_the_token(client: Client, google: FakeGoogle) -> None:
    sign_in(client, google)
    SocialAccount.objects.update(encrypted_access_token="enc:elats")

    authorization = google.authorize(csrf_post(client, "/auth/google/link/"))
    google.callback(client, authorization)

    assert SocialAccount.objects.count() == 1
    assert SocialAccount.objects.get().access_token == "google-access-token"


@pytest.mark.django_db(transaction=True)
def test_without_the_setting_sign_in_keeps_no_token(
    client: Client, google: FakeGoogle
) -> None:
    sign_in(client, google)

    row = SocialAccount.objects.get()
    assert row.encrypted_access_token is None
    assert row.access_token is None


# Settings


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ("yes", "['PROVIDER_TOKENS'] must be a dict"),
        ({"encrypt": TOKENS["encrypt"]}, "needs exactly the keys"),
        ({**TOKENS, "key": "x"}, "needs exactly the keys"),
        ({**TOKENS, "encrypt": print}, "['encrypt'] must be the dotted path"),
        (
            {**TOKENS, "decrypt": "tests.django.token_crypto.NOT_CALLABLE"},
            "['decrypt'] 'tests.django.token_crypto.NOT_CALLABLE' is not callable",
        ),
        ({**TOKENS, "decrypt": "tests.django.token_crypto.missing"}, "missing"),
    ],
)
def test_invalid_provider_token_settings_are_errors(
    value: object, message: str
) -> None:
    with override_settings(CROSS_AUTH={"PROVIDER_TOKENS": value}):
        errors = check_settings()

    assert [error.id for error in errors] == ["cross_auth.E001"]
    assert errors[0].level == checks.ERROR
    assert message in errors[0].msg


def test_provider_tokens_need_time_zone_support() -> None:
    with override_settings(CROSS_AUTH={"PROVIDER_TOKENS": TOKENS}, USE_TZ=False):
        errors = check_settings()

    assert errors[0].msg == "CROSS_AUTH['PROVIDER_TOKENS'] needs USE_TZ = True"


def test_valid_provider_token_settings_pass() -> None:
    with override_settings(CROSS_AUTH={"PROVIDER_TOKENS": TOKENS}):
        assert check_settings() == []
