"""Seed and inspect the Django example through its test-only management app."""

import json

from django.contrib.auth.models import User
from django.core.management.base import BaseCommand, CommandError, CommandParser
from django.db.models import Q

from cross_auth.django.models import SocialAccount


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


class Command(BaseCommand):
    help = "Seed password users or read account facts for the browser tests."

    def add_arguments(self, parser: CommandParser) -> None:
        operations = parser.add_subparsers(dest="operation", required=True)
        seed = operations.add_parser("seed-password-user")
        seed.add_argument("email")
        seed.add_argument("password")
        read = operations.add_parser("facts")
        read.add_argument("email")

    def handle(self, *args: object, **options: object) -> str | None:
        match options:
            case {
                "operation": "seed-password-user",
                "email": str(email),
                "password": str(password),
            }:
                seed_password_user(email, password)
                return None
            case {"operation": "facts", "email": str(email)}:
                return json.dumps(facts(email))
            case _:
                raise CommandError("Unknown E2E state operation.")
