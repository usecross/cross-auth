"""Seeds and reads the FastAPI example's database for the shared browser suite.

    state.py seed-password-user EMAIL PASSWORD
    state.py facts EMAIL

Works on the worker's SQLite file (``E2E_DATABASE``), without importing the app
(importing it would seed the demo users again), and prints JSON. ``facts``
opens the database read-only.
"""

import json
import os
import sqlite3
import sys

from passlib.context import CryptContext

DATABASE = os.environ["E2E_DATABASE"]


def seed_password_user(email: str, password: str) -> None:
    # The columns the example's User model gives a password user.
    hashed = CryptContext(schemes=["bcrypt"]).hash(password)
    with sqlite3.connect(DATABASE) as db:
        db.execute(
            "INSERT INTO user (email, email_verified, hashed_password, display_name)"
            " VALUES (?, 1, ?, ?)",
            (email, hashed, email),
        )


def facts(email: str) -> dict[str, object]:
    with sqlite3.connect(f"file:{DATABASE}?mode=ro", uri=True) as db:
        users = db.execute(
            "SELECT id, hashed_password IS NOT NULL FROM user"
            " WHERE lower(email) = lower(?) ORDER BY id",
            (email,),
        ).fetchall()
        user_ids = [user_id for user_id, _ in users]
        accounts = db.execute(
            "SELECT user_id, provider_user_id, provider_email FROM socialaccount"
            " WHERE provider = 'google' AND (lower(provider_email) = lower(?)"
            f" OR user_id IN ({', '.join('?' * len(user_ids))})) ORDER BY id",
            (email, *user_ids),
        ).fetchall()
    return {
        "users": [
            {"id": str(user_id), "has_password": bool(has_password)}
            for user_id, has_password in users
        ],
        "google_accounts": [
            {
                "user_id": str(user_id),
                "provider_user_id": provider_user_id,
                "provider_email": provider_email,
            }
            for user_id, provider_user_id, provider_email in accounts
        ],
    }


match sys.argv[1:]:
    case ["seed-password-user", email, password]:
        seed_password_user(email, password)
    case ["facts", email]:
        print(json.dumps(facts(email)))
    case _:
        sys.exit(__doc__)
