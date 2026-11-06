"""Shared Django test helpers; importing this module collects no tests."""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Any, TypeVar

from django.conf import settings
from django.contrib.auth.base_user import AbstractBaseUser
from django.db import connections
from django.http import HttpResponseBase
from django.test import Client

from cross_auth._storage import SocialAccountCreate
from cross_auth.django.models import SocialAccount
from cross_auth.django.storage import DjangoAccountsStorage

from .fake_google import Account, Authorization, FakeGoogle

CUSTOM_USER = settings.AUTH_USER_MODEL != "auth.User"
_T = TypeVar("_T")


def make_user(
    email: str,
    *,
    password: str | None = None,
    is_active: bool = True,
    using: str | None = None,
) -> AbstractBaseUser:
    """Create a user the way the application itself would."""
    user: AbstractBaseUser
    if CUSTOM_USER:
        from tests.django.custom_user.models import User as CustomUser

        user = CustomUser.objects.db_manager(using).create_user(
            email, display_name="Test", password=password
        )
    else:
        from django.contrib.auth.models import User

        user = User.objects.db_manager(using).create_user(
            email, email=email, password=password
        )
    if not is_active:
        user.is_active = False
        user.save(using=using)
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
    assert not any(thread.is_alive() for thread in threads), "database workers hung"
    return results


def interleave_after_write(
    first: Callable[[], _T], second: Callable[[], _T]
) -> list[_T | BaseException]:
    """Pause a writer after its first SQL write until a competitor enters SQL.

    Each operation has its own real connection. No sleeps or adapter-private
    hooks: the first operation holds its database lock while the second starts.
    """
    written = threading.Event()
    competing = threading.Event()

    def run(index: int) -> _T:
        connection = connections["default"]
        paused = False

        def execute(
            execute: Callable[..., Any],
            sql: str,
            params: Any,
            many: bool,
            context: dict[str, Any],
        ) -> Any:
            nonlocal paused
            if index == 1 and sql.lstrip().upper().startswith(
                ("UPDATE ", "INSERT ", "DELETE ", "SELECT ")
            ):
                competing.set()
            result = execute(sql, params, many, context)
            if (
                index == 0
                and not paused
                and sql.lstrip().upper().startswith(("UPDATE ", "INSERT ", "DELETE "))
            ):
                paused = True
                written.set()
                assert competing.wait(timeout=10), "competitor never entered SQL"
            return result

        if index == 1:
            assert written.wait(timeout=10), "first operation never wrote"
        with connection.execute_wrapper(execute):
            return first() if index == 0 else second()

    return run_in_threads(2, run)


def csrf_post(client: Client, path: str, data: dict[str, str] | None = None) -> Any:
    if "csrftoken" not in client.cookies:
        client.get("/")
    token = client.cookies["csrftoken"].value
    return client.post(path, {**(data or {}), "csrfmiddlewaretoken": token})


def whoami(client: Client) -> dict[str, Any]:
    return client.get("/").json()


def start_login(
    client: Client, google: FakeGoogle, next_url: str | None = None
) -> Authorization:
    data = {"next": next_url} if next_url is not None else {}
    return google.authorize(csrf_post(client, "/auth/google/login/", data))


def sign_in(
    client: Client, google: FakeGoogle, account: Account | None = None
) -> HttpResponseBase:
    return google.callback(client, start_login(client, google), account)
