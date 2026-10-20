import os

from django.core.exceptions import PermissionDenied
from django.dispatch import receiver

from cross_auth.django.signals import before_callback, user_created

# For example ALLOWED_EMAIL_DOMAIN=example.com. Unset, everyone may sign in.
ALLOWED_EMAIL_DOMAIN = os.environ.get("ALLOWED_EMAIL_DOMAIN")


@receiver(before_callback)
def only_company_accounts(sender, email, email_verified, **kwargs):
    if ALLOWED_EMAIL_DOMAIN and not (
        email_verified and (email or "").lower().endswith("@" + ALLOWED_EMAIL_DOMAIN)
    ):
        raise PermissionDenied("Use your company account.")


@receiver(user_created)
def welcome(sender, user, **kwargs):
    print(f"Welcome, new user {user.pk} ({user.email})")
