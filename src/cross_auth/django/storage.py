"""Django ORM implementations of Cross Auth's storage protocols.

Each method runs its own ``transaction.atomic`` on the database the router
picks for writes, so it commits before returning in autocommit views. Called
inside an application's atomic block, writes join that transaction and
``on_commit`` waits for its outermost commit, as Django does.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import IntegrityError, router, transaction
from django.db.models import F, Q
from django.utils import timezone

from cross_auth._storage import (
    CommitCallback,
    DisconnectResult,
    SocialAccountCreate,
    UserCreate,
)
from cross_auth._storage import User as CrossAuthUser
from cross_auth.exceptions import CrossAuthException

from .conf import get_settings
from .models import ExpiringValue, SocialAccount

if TYPE_CHECKING:
    from django.contrib.auth.base_user import AbstractBaseUser
    from django.db.models import Model, QuerySet


class DjangoUser:
    """Cross Auth's view of a native Django user.

    Core reads a few user values under its own names. Django has no
    verified-email flag, so ``email_verified`` is always False; verified
    provider emails stay on each ``SocialAccount``. The password hash is never
    exposed.
    """

    __slots__ = ("native", "_password_login")

    def __init__(self, native: AbstractBaseUser, *, password_login: bool) -> None:
        self.native = native
        self._password_login = password_login

    @property
    def id(self) -> Any:
        return self.native.pk

    @property
    def email(self) -> str | None:
        # EMAIL_FIELD is configured per user model.
        value = getattr(self.native, self.native.get_email_field_name(), None)
        return value or None

    @property
    def email_verified(self) -> bool:
        return False

    @property
    def hashed_password(self) -> str | None:
        return None

    @property
    def has_usable_password(self) -> bool:
        return self._password_login and self.native.has_usable_password()


_NO_MATCH = object()


def _coerce_pk(model: type[Model], value: object) -> object:
    """Convert an ID from a URL or stored state, or return ``_NO_MATCH``."""
    try:
        return model._meta.pk.to_python(value)
    except (TypeError, ValueError, ValidationError):
        return _NO_MATCH


def _check_no_extra_fields(extra_fields: Mapping[str, Any] | None) -> None:
    if extra_fields:
        raise TypeError(
            "The Django SocialAccount model has no extra fields; got "
            f"{sorted(extra_fields)!r} from a social_account hook"
        )


class DjangoAccountsStorage:
    """Stores identities in ``cross_auth.SocialAccount`` next to native users."""

    @property
    def _user_model(self) -> type[AbstractBaseUser]:
        return get_user_model()

    @property
    def alias(self) -> str:
        # Identities reference users, so both live on the user model's database.
        return router.db_for_write(self._user_model)

    def _users(self) -> QuerySet[AbstractBaseUser]:
        return self._user_model._default_manager.using(self.alias)

    def _accounts(self) -> QuerySet[SocialAccount]:
        return SocialAccount.objects.using(self.alias)

    def _wrap(self, native: AbstractBaseUser) -> DjangoUser:
        return DjangoUser(native, password_login=get_settings().password_login)

    def on_commit(self, callback: CommitCallback) -> None:
        transaction.on_commit(callback, using=self.alias, robust=False)

    def find_user_by_email(self, email: str) -> DjangoUser | None:
        email_field = self._user_model.get_email_field_name()
        matches = list(self._users().filter(**{f"{email_field}__iexact": email})[:2])
        if len(matches) > 1:
            raise CrossAuthException(
                "account_not_linked",
                error_description=(
                    "Several accounts use this email. Sign in and connect the "
                    "provider from your account."
                ),
            )
        return self._wrap(matches[0]) if matches else None

    def find_user_by_id(self, id: Any) -> DjangoUser | None:
        pk = _coerce_pk(self._user_model, id)
        if pk is _NO_MATCH:
            return None
        native = self._users().filter(pk=pk).first()
        return self._wrap(native) if native is not None else None

    def find_social_account(
        self,
        *,
        provider: str,
        provider_user_id: str,
        user_id: Any | None = None,
        is_login_method: bool | None = None,
    ) -> SocialAccount | None:
        accounts = self._accounts().filter(
            provider=provider, provider_user_id=provider_user_id
        )
        if user_id is not None:
            pk = _coerce_pk(self._user_model, user_id)
            if pk is _NO_MATCH:
                return None
            accounts = accounts.filter(user_id=pk)
        if is_login_method is not None:
            accounts = accounts.filter(is_login_method=is_login_method)
        # The unique identity constraint allows at most one row.
        return accounts.first()

    def has_social_account(self, *, provider: str, provider_user_id: str) -> bool:
        return (
            self._accounts()
            .filter(provider=provider, provider_user_id=provider_user_id)
            .exists()
        )

    def find_social_account_by_id(self, social_account_id: Any) -> SocialAccount | None:
        pk = _coerce_pk(SocialAccount, social_account_id)
        if pk is _NO_MATCH:
            return None
        return self._accounts().filter(pk=pk).first()

    def list_social_accounts(self, *, user_id: Any) -> list[SocialAccount]:
        pk = _coerce_pk(self._user_model, user_id)
        if pk is _NO_MATCH:
            return []
        return list(self._accounts().filter(user_id=pk).order_by("pk"))

    def create_user_with_identity(
        self,
        *,
        user: UserCreate,
        identity: Callable[[CrossAuthUser], SocialAccountCreate],
    ) -> tuple[DjangoUser, SocialAccount]:
        """Create the user, the rows its factory writes, and the identity.

        All of them commit together or not at all. When a concurrent sign-in
        stored the same identity first, the database rejects this one and
        everything rolls back.
        """
        factory = get_settings().create_user
        data: SocialAccountCreate | None = None
        try:
            with transaction.atomic(using=self.alias):
                native = factory(
                    email=user["email"],
                    user_info=user["user_info"],
                    extra_fields=user["extra_fields"] or {},
                )
                created = self._wrap(native)
                data = identity(created)
                if _coerce_pk(self._user_model, data["user_id"]) != native.pk:
                    raise ValueError("Initial identity must belong to the new user")
                _check_no_extra_fields(data["extra_fields"])
                account = self._accounts().create(
                    user_id=native.pk,
                    provider=data["provider"],
                    provider_user_id=data["provider_user_id"],
                    provider_email=data["provider_email"],
                    provider_email_verified=data["provider_email_verified"],
                    is_login_method=data["is_login_method"],
                )
        except IntegrityError as error:
            if data is not None and self.has_social_account(
                provider=data["provider"], provider_user_id=data["provider_user_id"]
            ):
                raise CrossAuthException("account_already_linked") from error
            raise
        return created, account

    def create_social_account(
        self,
        *,
        user_id: Any,
        provider: str,
        provider_user_id: str,
        access_token: str | None,
        refresh_token: str | None,
        access_token_expires_at: datetime | None,
        refresh_token_expires_at: datetime | None,
        scope: str | None,
        user_info: dict[str, Any],
        provider_email: str | None,
        provider_email_verified: bool | None,
        is_login_method: bool,
        extra_fields: Mapping[str, Any] | None = None,
    ) -> SocialAccount:
        _check_no_extra_fields(extra_fields)
        pk = _coerce_pk(self._user_model, user_id)
        if pk is _NO_MATCH:
            raise ValueError(f"Invalid user ID {user_id!r}")
        try:
            with transaction.atomic(using=self.alias):
                return self._accounts().create(
                    user_id=pk,
                    provider=provider,
                    provider_user_id=provider_user_id,
                    provider_email=provider_email,
                    provider_email_verified=provider_email_verified,
                    is_login_method=is_login_method,
                )
        except IntegrityError as error:
            existing = self.find_social_account(
                provider=provider, provider_user_id=provider_user_id, user_id=pk
            )
            if existing is None:
                if self.has_social_account(
                    provider=provider, provider_user_id=provider_user_id
                ):
                    raise CrossAuthException("account_already_linked") from error
                raise
            if is_login_method and not existing.is_login_method:
                raise CrossAuthException("account_already_linked") from error
            # A same-owner retry keeps the stored row unchanged.
            return existing

    def update_social_account(
        self,
        social_account_id: Any,
        *,
        access_token: str | None,
        refresh_token: str | None,
        access_token_expires_at: datetime | None,
        refresh_token_expires_at: datetime | None,
        scope: str | None,
        user_info: dict[str, Any],
        provider_email: str | None,
        provider_email_verified: bool | None,
        enable_login: bool = False,
        extra_fields: Mapping[str, Any] | None = None,
    ) -> SocialAccount:
        _check_no_extra_fields(extra_fields)
        pk = _coerce_pk(SocialAccount, social_account_id)
        values: dict[str, Any] = {
            "provider_email": provider_email,
            "provider_email_verified": provider_email_verified,
            "updated_at": timezone.now(),
        }
        # Exclusive identity ownership means promotion cannot create a second
        # login owner.
        if enable_login:
            values["is_login_method"] = True
        # One UPDATE statement: SQLite cannot upgrade a read transaction to a
        # write while another connection is writing.
        if pk is _NO_MATCH or self._accounts().filter(pk=pk).update(**values) == 0:
            raise ValueError(f"Social account {social_account_id!r} does not exist")
        return self._accounts().get(pk=pk)

    def disconnect_social_account(
        self,
        *,
        user_id: Any,
        provider: str,
        social_account_id: Any,
    ) -> DisconnectResult:
        """Remove an owned identity unless it is the user's last way to sign in.

        A no-op update of the user row is the first statement, so same-user
        disconnects serialize: PostgreSQL holds the row lock until commit and
        SQLite takes its write lock before reading anything that could go
        stale. ``select_for_update`` alone is a no-op on SQLite.
        """
        user_model = self._user_model
        user_pk = _coerce_pk(user_model, user_id)
        account_pk = _coerce_pk(SocialAccount, social_account_id)
        if user_pk is _NO_MATCH or account_pk is _NO_MATCH:
            return "not_found"

        pk_name = user_model._meta.pk.name
        with transaction.atomic(using=self.alias):
            users = self._users().filter(pk=user_pk)
            if users.update(**{pk_name: F(pk_name)}) == 0:
                return "not_found"
            native = users.first()
            account = (
                self._accounts()
                .filter(pk=account_pk, user_id=user_pk, provider=provider)
                .first()
            )
            if native is None or account is None:
                return "not_found"

            if account.is_login_method and not self._wrap(native).has_usable_password:
                has_alternative = (
                    self._accounts()
                    .filter(user_id=user_pk, is_login_method=True)
                    .exclude(pk=account.pk)
                    .exists()
                )
                if not has_alternative:
                    return "last_login_method"

            account.delete()
        return "disconnected"


class DjangoSecondaryStorage:
    """Expiring key/value storage on the ``cross_auth.ExpiringValue`` table.

    ``pop`` is a compare-and-delete: concurrent callers may all read a value,
    but only the one whose DELETE removes the row receives it.
    """

    @property
    def alias(self) -> str:
        return router.db_for_write(ExpiringValue)

    def _values(self) -> QuerySet[ExpiringValue]:
        return ExpiringValue.objects.using(self.alias)

    def _live(self, key: str) -> QuerySet[ExpiringValue]:
        return self._values().filter(
            Q(expires_at__isnull=True) | Q(expires_at__gt=timezone.now()), key=key
        )

    def set(self, key: str, value: str, ttl: int | None = None) -> None:
        now = timezone.now()
        expires_at = now + timedelta(seconds=ttl) if ttl is not None else None
        self._values().filter(expires_at__lte=now).delete()
        # Write first rather than read-then-write, which SQLite cannot upgrade
        # while another connection writes. Concurrent sets: the last one wins.
        values = {"value": value, "expires_at": expires_at}
        if self._values().filter(key=key).update(**values):
            return
        try:
            with transaction.atomic(using=self.alias):
                self._values().create(key=key, **values)
        except IntegrityError:
            self._values().filter(key=key).update(**values)

    def get(self, key: str) -> str | None:
        return self._live(key).values_list("value", flat=True).first()

    def delete(self, key: str) -> None:
        self._values().filter(key=key).delete()

    def pop(self, key: str) -> str | None:
        value = self.get(key)
        if value is None:
            return None
        deleted, _ = self._live(key).filter(value=value).delete()
        return value if deleted else None
