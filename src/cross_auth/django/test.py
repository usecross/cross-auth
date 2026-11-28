"""Test helpers for projects that use Cross Auth's two-factor authentication."""

from __future__ import annotations

from typing import Literal

from django.contrib.auth.base_user import AbstractBaseUser
from django.test import Client

from .sessions import MFA_METHOD_SESSION_KEY
from .views import mfa_checked


def login_with_mfa(
    client: Client,
    user: AbstractBaseUser,
    *,
    method: Literal["totp", "recovery_code"] = "totp",
    backend: str | None = None,
) -> None:
    """``client.force_login(user)`` for a user with 2FA, as if they passed it.

    ``force_login()`` and ``login()`` leave such a user anonymous: the 2FA
    guard holds back every Django login of theirs until the verify page.
    """
    checked = mfa_checked.set(True)
    try:
        client.force_login(user, backend=backend)
    finally:
        mfa_checked.reset(checked)
    session = client.session
    session[MFA_METHOD_SESSION_KEY] = method
    session.save()
