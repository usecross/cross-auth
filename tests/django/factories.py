from collections.abc import Mapping
from typing import Any

from django.conf import settings
from django.contrib.auth.base_user import AbstractBaseUser

from cross_auth.django.conf import create_user

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
