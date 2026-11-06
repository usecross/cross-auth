"""Account creation and session management stay on their authoritative database."""

from __future__ import annotations

from typing import Any

import pytest
from django.conf import settings
from django.contrib.auth import get_user_model, login
from django.core.exceptions import ImproperlyConfigured
from django.db import transaction
from django.db.models import Model
from django.test import RequestFactory, override_settings

from cross_auth.django import signals
from cross_auth.django.models import Session, SocialAccount
from cross_auth.django.sessions import SessionStore, list_sessions, revoke_session
from cross_auth.django.storage import DjangoAccountsStorage, DjangoSecondaryStorage

from .support import CUSTOM_USER, identity_data, make_user
from .testapp.models import Profile

pytestmark = pytest.mark.django_db(transaction=True, databases=["default", "other"])


class PrimaryRouter:
    def db_for_read(self, model: type[Model], **hints: Any) -> str:
        # A stale replica must not participate in account/session decisions.
        return "default"

    def db_for_write(self, model: type[Model], **hints: Any) -> str:
        return "other"


class SplitIdentityRouter(PrimaryRouter):
    def db_for_write(self, model: type[Model], **hints: Any) -> str:
        return "default" if model is SocialAccount else "other"


def signup(storage: DjangoAccountsStorage) -> None:
    storage.create_user_with_identity(
        user={
            "email": "person@example.com",
            "user_info": {},
            "email_verified": True,
            "extra_fields": {},
        },
        identity=lambda user: identity_data(user.id),
    )


def test_split_native_and_identity_routes_are_rejected_before_factory() -> None:
    with override_settings(DATABASE_ROUTERS=[SplitIdentityRouter()]):
        with pytest.raises(ImproperlyConfigured, match="share a write database"):
            DjangoAccountsStorage()
    assert get_user_model()._default_manager.using("other").count() == 0


@pytest.mark.parametrize("factory", ["return_unsaved", "return_wrong_database"])
def test_factory_must_return_saved_native_user_on_captured_database(
    factory: str,
) -> None:
    make_user("existing@example.com")
    with override_settings(
        DATABASE_ROUTERS=[PrimaryRouter()],
        CROSS_AUTH={"CREATE_USER": f"tests.django.factories.{factory}"},
    ):
        with pytest.raises(ImproperlyConfigured, match="saved AUTH_USER_MODEL"):
            signup(DjangoAccountsStorage())
    assert not SocialAccount.objects.using("other").exists()
    assert not get_user_model()._default_manager.using("other").exists()


def test_default_factory_uses_the_captured_database() -> None:
    if CUSTOM_USER:
        pytest.skip("Custom user model supplies its own factory")
    with override_settings(CROSS_AUTH={}):
        with override_settings(DATABASE_ROUTERS=[PrimaryRouter()]):
            storage = DjangoAccountsStorage()
        signup(storage)
    assert get_user_model()._default_manager.using("other").count() == 1
    assert not get_user_model()._default_manager.using("default").exists()


def test_signup_queries_and_commit_callbacks_keep_the_captured_database() -> None:
    calls: list[str] = []
    with override_settings(
        CROSS_AUTH={"CREATE_USER": "tests.django.factories.create_native"},
    ):
        with override_settings(DATABASE_ROUTERS=[PrimaryRouter()]):
            storage = DjangoAccountsStorage()
            secondary = DjangoSecondaryStorage()
        # Routing changes cannot move part of an existing storage operation.
        assert storage.alias == secondary.alias == "other"
        with transaction.atomic(using="other"):
            signup(storage)
            assert storage.find_user_by_email("person@example.com") is not None
            assert (
                storage.find_social_account(
                    provider="google", provider_user_id="google-sub-1"
                )
                is not None
            )
            storage.on_commit(lambda: calls.append("created"))
            assert not calls
    assert calls == ["created"]
    assert Profile.objects.using("other").count() == 1
    assert not get_user_model()._default_manager.using("default").exists()
    secondary.set("state", "value")
    assert secondary.pop("state") == "value"


def test_current_session_logout_uses_captured_database() -> None:
    with override_settings(
        DATABASE_ROUTERS=[PrimaryRouter()],
        SESSION_ENGINE="cross_auth.django.sessions",
    ):
        user = make_user("person@example.com")
        request = RequestFactory().get("/")
        request.session = SessionStore()
        login(request, user, backend=settings.AUTHENTICATION_BACKENDS[0])
        request.user = user
        request.session.save()
    [session] = list_sessions(request)
    assert revoke_session(request, session.id)
    assert not request.user.is_authenticated
    assert not Session.objects.using("other").exists()


def test_session_engine_listing_revocation_and_signal_use_one_database() -> None:
    calls: list[str] = []
    with override_settings(
        DATABASE_ROUTERS=[PrimaryRouter()],
        SESSION_ENGINE="cross_auth.django.sessions",
    ):
        user = make_user("person@example.com")
        request = RequestFactory().get("/")
        request.session = SessionStore()
        login(request, user, backend=settings.AUTHENTICATION_BACKENDS[0])
        request.user = user
        request.session.save()
        restored = SessionStore(request.session.session_key)
        other = RequestFactory().get("/")
        other.session = SessionStore()
        login(other, user, backend=settings.AUTHENTICATION_BACKENDS[0])
        other.session.save()
    # Store reads/deletes and management queries retain the same database even
    # when the write router would now pick the empty default database.
    assert SessionStore(request.session.session_key).load() == {}
    assert restored.load()
    assert restored.exists(request.session.session_key or "")
    sessions = list_sessions(request)
    assert len(sessions) == 2
    target = next(session for session in sessions if not session.is_current)

    def revoked(**kwargs: Any) -> None:
        calls.append("revoked")

    signals.session_revoked.connect(revoked)
    try:
        with transaction.atomic(using="other"):
            assert revoke_session(request, target.id)
            assert not calls
        assert calls == ["revoked"]
        assert len(list_sessions(request)) == 1
        assert Session.objects.using("other").count() == 1
        assert not Session.objects.using("default").exists()
    finally:
        signals.session_revoked.disconnect(revoked)
