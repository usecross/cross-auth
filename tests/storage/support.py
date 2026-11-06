"""Shared account construction for storage transaction contracts."""

from typing import Any

from sqlalchemy import func
from sqlmodel import Session, select

from cross_auth.storage.sqlmodel import SQLModelAccountsStorage

from .models import SignupApplicationRow, SocialAccount, User


def row_counts(engine):
    with Session(engine) as session:
        return tuple(
            session.exec(select(func.count()).select_from(model)).one()
            for model in (User, SocialAccount, SignupApplicationRow)
        )


def user_data(email):
    return {
        "email": email,
        "email_verified": True,
        "user_info": {},
        "extra_fields": None,
    }


def identity_data(user, subject):
    assert user.id is not None
    return {
        "user_id": str(user.id),
        "provider": "github",
        "provider_user_id": subject,
        "access_token": "secret",
        "refresh_token": None,
        "access_token_expires_at": None,
        "refresh_token_expires_at": None,
        "scope": None,
        "user_info": {},
        "provider_email": user.email,
        "provider_email_verified": True,
        "is_login_method": True,
        "extra_fields": None,
    }


def make_store(engine, label, failure=None):
    class ApplicationStore(SQLModelAccountsStorage[User, SocialAccount]):
        def build_user(self, *, session, **kwargs):
            user = super().build_user(session=session, **kwargs)
            if failure == "user":
                # Deliberately violate the application's non-null column.
                user.email = None  # ty: ignore[invalid-assignment]
            application_values: dict[str, Any] = {
                "user": user,
                "label": None if failure == "application" else label,
            }
            session.add(SignupApplicationRow(**application_values))
            return user

    return ApplicationStore(
        User, SocialAccount, session_factory=lambda: Session(engine)
    )
