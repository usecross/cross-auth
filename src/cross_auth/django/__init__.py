"""Native Django integration for Cross Auth.

Add ``"cross_auth.django"`` to ``INSTALLED_APPS`` to store provider identities
and short-lived OAuth state with the Django ORM. Django keeps owning users,
passwords, permissions, sessions, login, and logout.

This package does not import models at import time, so settings modules can
import Cross Auth providers before Django's app registry is ready.
"""

from ._login_method import get_login_method

__all__ = ["get_login_method"]
