import uuid
from collections.abc import Mapping
from typing import Any, ClassVar

from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.contrib.auth.models import PermissionsMixin
from django.db import models


class UserManager(BaseUserManager["User"]):
    def create_user(
        self, email: str, display_name: str, password: str | None = None
    ) -> "User":
        user = self.model(email=self.normalize_email(email), display_name=display_name)
        user.set_password(password)
        user.save(using=self._db)
        return user


class User(AbstractBaseUser, PermissionsMixin):
    """A UUID user that signs in by email and requires a display name."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True)
    display_name = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)

    USERNAME_FIELD = "email"
    EMAIL_FIELD = "email"
    REQUIRED_FIELDS: ClassVar[list[str]] = ["display_name"]

    objects = UserManager()


def create_user(
    *, email: str, user_info: Mapping[str, Any], extra_fields: Mapping[str, Any]
) -> User:
    return User.objects.create_user(
        email, display_name=user_info.get("name") or email.split("@")[0]
    )
