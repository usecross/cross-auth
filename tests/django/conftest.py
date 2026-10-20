from __future__ import annotations

import threading
from collections.abc import Callable, Iterator
from typing import Any, TypeVar

import pytest
from django.conf import settings
from django.contrib.auth.base_user import AbstractBaseUser
from django.db import connections

from cross_auth._storage import SocialAccountCreate
from cross_auth.django.models import SocialAccount
from cross_auth.django.storage import DjangoAccountsStorage, DjangoSecondaryStorage

CUSTOM_USER = settings.AUTH_USER_MODEL != "auth.User"

_T = TypeVar("_T")


@pytest.fixture
def storage() -> DjangoAccountsStorage:
    return DjangoAccountsStorage()


@pytest.fixture
def secondary() -> DjangoSecondaryStorage:
    return DjangoSecondaryStorage()


def make_user(
    email: str, *, password: str | None = None, is_active: bool = True
) -> AbstractBaseUser:
    """Create a user the way the application itself would."""
    user: AbstractBaseUser
    if CUSTOM_USER:
        from tests.django.custom_user.models import User as CustomUser

        user = CustomUser.objects.create_user(
            email, display_name="Test", password=password
        )
    else:
        from django.contrib.auth.models import User

        user = User.objects.create_user(email, email=email, password=password)
    if not is_active:
        user.is_active = False
        user.save()
    return user


def identity_data(
    user_id: Any,
    *,
    provider: str = "google",
    provider_user_id: str = "google-sub-1",
    email: str | None = "person@example.com",
    is_login_method: bool = True,
) -> SocialAccountCreate:
    return SocialAccountCreate(
        user_id=user_id,
        provider=provider,
        provider_user_id=provider_user_id,
        access_token="access",
        refresh_token="refresh",
        access_token_expires_at=None,
        refresh_token_expires_at=None,
        scope="openid email profile",
        user_info={"id": provider_user_id, "email": email, "email_verified": True},
        provider_email=email,
        provider_email_verified=True,
        is_login_method=is_login_method,
        extra_fields={},
    )


def create_account(
    storage: DjangoAccountsStorage, data: SocialAccountCreate
) -> SocialAccount:
    return storage.create_social_account(
        user_id=data["user_id"],
        provider=data["provider"],
        provider_user_id=data["provider_user_id"],
        access_token=data["access_token"],
        refresh_token=data["refresh_token"],
        access_token_expires_at=data["access_token_expires_at"],
        refresh_token_expires_at=data["refresh_token_expires_at"],
        scope=data["scope"],
        user_info=data["user_info"],
        provider_email=data["provider_email"],
        provider_email_verified=data["provider_email_verified"],
        is_login_method=data["is_login_method"],
        extra_fields=data["extra_fields"],
    )


def update_account(
    storage: DjangoAccountsStorage,
    account: SocialAccount,
    *,
    provider_email: str = "new@example.com",
    enable_login: bool = False,
) -> SocialAccount:
    return storage.update_social_account(
        account.pk,
        access_token=None,
        refresh_token=None,
        access_token_expires_at=None,
        refresh_token_expires_at=None,
        scope=None,
        user_info={},
        provider_email=provider_email,
        provider_email_verified=True,
        enable_login=enable_login,
    )


def connect(
    user: AbstractBaseUser,
    *,
    provider: str = "google",
    provider_user_id: str = "google-sub-1",
    is_login_method: bool = True,
) -> SocialAccount:
    return SocialAccount.objects.create(
        user=user,
        provider=provider,
        provider_user_id=provider_user_id,
        provider_email="person@example.com",
        provider_email_verified=True,
        is_login_method=is_login_method,
    )


def run_in_threads(count: int, target: Callable[[int], _T]) -> list[_T | BaseException]:
    """Run ``target(index)`` concurrently, each thread on its own connection."""
    results: list[_T | BaseException] = [RuntimeError("did not run")] * count
    start = threading.Barrier(count)

    def run(index: int) -> None:
        try:
            start.wait(timeout=10)
            results[index] = target(index)
        except BaseException as error:  # noqa: BLE001 - reported to the test
            results[index] = error
        finally:
            connections.close_all()

    threads = [threading.Thread(target=run, args=(index,)) for index in range(count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    return results


@pytest.fixture
def is_postgres() -> Iterator[bool]:
    yield connections["default"].vendor == "postgresql"
