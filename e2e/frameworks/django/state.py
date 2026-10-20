"""Seeds and reads the Django example's database for the shared browser suite.

    state.py seed-password-user EMAIL PASSWORD
    state.py facts EMAIL

Runs with the same settings and database as the worker's server and prints
JSON. ``facts`` only reads.
"""

import json
import sys

import django

django.setup()

from django.contrib.auth.models import User  # noqa: E402
from django.db.models import Q  # noqa: E402

from cross_auth.django.models import SocialAccount  # noqa: E402


def seed_password_user(email: str, password: str) -> None:
    # Like the default Cross Auth factory, the username is the email.
    User.objects.create_user(email, email=email, password=password)


def facts(email: str) -> dict[str, object]:
    users = User.objects.filter(email__iexact=email)
    accounts = SocialAccount.objects.filter(provider="google").filter(
        Q(user__in=users) | Q(provider_email__iexact=email)
    )
    return {
        "users": [
            {"id": str(user.pk), "has_password": user.has_usable_password()}
            for user in users.order_by("pk")
        ],
        "google_accounts": [
            {
                "user_id": str(account.user_id),
                "provider_user_id": account.provider_user_id,
                "provider_email": account.provider_email,
            }
            for account in accounts.order_by("pk")
        ],
    }


match sys.argv[1:]:
    case ["seed-password-user", email, password]:
        seed_password_user(email, password)
    case ["facts", email]:
        print(json.dumps(facts(email)))
    case _:
        sys.exit(__doc__)
