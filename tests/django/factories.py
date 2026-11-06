from collections.abc import Mapping
from typing import Any

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.base_user import AbstractBaseUser

from cross_auth.django.conf import create_user, user_database

from .support import make_user
from .testapp.models import Profile


def with_profile(
    *, email: str, user_info: Mapping[str, Any], extra_fields: Mapping[str, Any]
) -> AbstractBaseUser:
    """Create the user and an application row in the same transaction."""
    if settings.AUTH_USER_MODEL == "custom_user.User":
        from .custom_user.models import create_user as create_custom_user

        user: AbstractBaseUser = create_custom_user(
            email=email, user_info=user_info, extra_fields=extra_fields
        )
    else:
        user = create_user(email=email, user_info=user_info, extra_fields=extra_fields)
    Profile.objects.create(user=user, display_name=user_info.get("name", ""))
    return user


def create_native(
    *, email: str, user_info: Mapping[str, Any], extra_fields: Mapping[str, Any]
) -> AbstractBaseUser:
    user = make_user(email, using=user_database())
    Profile.objects.using(user_database()).create(user=user, display_name="Profile")
    return user


def return_unsaved(
    *, email: str, user_info: Mapping[str, Any], extra_fields: Mapping[str, Any]
) -> AbstractBaseUser:
    return get_user_model()()


def return_wrong_database(
    *, email: str, user_info: Mapping[str, Any], extra_fields: Mapping[str, Any]
) -> AbstractBaseUser:
    return get_user_model()._default_manager.using("default").get()


def with_duplicate_profile(
    *, email: str, user_info: Mapping[str, Any], extra_fields: Mapping[str, Any]
) -> AbstractBaseUser:
    """Fail on an application row with an IntegrityError unrelated to signup."""
    user = with_profile(email=email, user_info=user_info, extra_fields=extra_fields)
    Profile.objects.create(user=user, display_name="duplicate")
    return user
