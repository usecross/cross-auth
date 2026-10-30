"""cross_auth.django.sessions through Django's test client and middleware.

Every test here runs with ``SESSION_ENGINE = "cross_auth.django.sessions"``
and its ``SessionMiddleware`` in place of Django's.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
import respx
import time_machine
from asgiref.sync import async_to_sync
from django.conf import settings
from django.contrib.auth import BACKEND_SESSION_KEY, SESSION_KEY, alogin
from django.contrib.auth.base_user import AbstractBaseUser
from django.core.exceptions import ImproperlyConfigured
from django.core.management import call_command
from django.db import IntegrityError, connection
from django.test import Client, RequestFactory, override_settings
from django.test.utils import CaptureQueriesContext

from cross_auth.django.models import Session
from cross_auth.django.sessions import (
    LOGIN_METHOD_SESSION_KEY,
    SessionStore,
    _clean_ip,
    _clean_user_agent,
)

from .conftest import connect, make_user
from .fake_google import FakeGoogle
from .test_views import csrf_post, sign_in, whoami

pytestmark = pytest.mark.django_db(transaction=True)

BACKEND = "cross_auth.django.backends.CrossAuthBackend"
PASSWORD_BACKEND = "django.contrib.auth.backends.ModelBackend"
USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_0) Chrome/130.0"
IP = "203.0.113.7"
T0 = datetime(2026, 10, 30, 12, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def cross_auth_sessions() -> Iterator[None]:
    middleware = [
        "cross_auth.django.sessions.SessionMiddleware"
        if name == "django.contrib.sessions.middleware.SessionMiddleware"
        else name
        for name in settings.MIDDLEWARE
    ]
    with override_settings(
        SESSION_ENGINE="cross_auth.django.sessions", MIDDLEWARE=middleware
    ):
        yield


@pytest.fixture
def google() -> Iterator[FakeGoogle]:
    with respx.mock(assert_all_called=False) as router:
        fake = FakeGoogle(router)
        fake.install()
        yield fake


def browser(user_agent: str | None = USER_AGENT, ip: str = IP) -> Client:
    headers = {"User-Agent": user_agent} if user_agent is not None else {}
    return Client(enforce_csrf_checks=True, headers=headers, REMOTE_ADDR=ip)


def stored(client: Client) -> Session:
    """The row of the client's session cookie."""
    return Session.objects.get(
        session_key=client.cookies[settings.SESSION_COOKIE_NAME].value
    )


def password_login(client: Client, email: str) -> None:
    response = csrf_post(
        client, "/accounts/login/", {"username": email, "password": "secret"}
    )
    assert response.status_code == 302, response.status_code


def password_user(email: str = "person@gmail.com") -> AbstractBaseUser:
    """A password user whom the default fake Google account signs in to."""
    user = make_user(email, password="secret")
    connect(user)
    return user


def listed(client: Client) -> list[dict[str, Any]]:
    return client.get("/sessions/").json()["sessions"]


def expire(client: Client) -> None:
    Session.objects.filter(pk=stored(client).pk).update(
        expire_date=T0 - timedelta(days=1)
    )


class TestColumns:
    def test_provider_sign_in(self, google: FakeGoogle) -> None:
        client = browser()

        sign_in(client, google)

        session = stored(client)
        assert str(session.user_id) == whoami(client)["user_id"]
        assert session.login_method == "google"
        assert session.user_agent == USER_AGENT
        assert session.ip == IP
        assert session.created_at <= session.last_activity
        assert Session.objects.count() == 1

    def test_password_login(self) -> None:
        user = make_user("person@example.com", password="secret")
        client = browser()

        password_login(client, "person@example.com")

        session = stored(client)
        assert session.user_id == user.pk
        assert session.login_method is None
        assert (session.user_agent, session.ip) == (USER_AGENT, IP)

    def test_later_password_login_clears_the_provider(self, google: FakeGoogle) -> None:
        user = password_user()
        client = browser()
        sign_in(client, google)
        assert stored(client).login_method == "google"

        # Same user, same session: Django's login() keeps the session's data,
        # including the provider Cross Auth recorded.
        password_login(client, "person@gmail.com")

        assert whoami(client)["backend"] == PASSWORD_BACKEND
        session = stored(client)
        assert session.user_id == user.pk
        assert session.login_method is None
        assert session.get_decoded()[LOGIN_METHOD_SESSION_KEY] == "google"
        assert Session.objects.count() == 1

        sign_in(client, google)

        assert stored(client).login_method == "google"

    def test_anonymous_session(self) -> None:
        client = browser()

        csrf_post(client, "/remember/")

        session = stored(client)
        assert session.user_id is None
        assert session.login_method is None
        assert (session.user_agent, session.ip) == (USER_AGENT, IP)

    def test_sanitized_user_agent_is_stored(self) -> None:
        client = browser(user_agent="Mozilla/5.0\x00 (X11;\r\n Linux)\t" + "x" * 600)

        csrf_post(client, "/remember/")

        user_agent = stored(client).user_agent
        assert user_agent is not None
        assert user_agent.startswith("Mozilla/5.0 (X11; Linux) xxx")
        assert len(user_agent) == 512

    def test_missing_user_agent_and_ip(self) -> None:
        client = browser(user_agent=None, ip="")

        csrf_post(client, "/remember/")

        assert (stored(client).user_agent, stored(client).ip) == (None, None)

    def test_store_without_a_request_keeps_the_device(self) -> None:
        client = browser()
        csrf_post(client, "/remember/")

        # Django's test client, like code outside a request, saves through a
        # store that never saw the request.
        session = client.session
        session["more"] = "data"
        session.save()

        assert (stored(client).user_agent, stored(client).ip) == (USER_AGENT, IP)
        assert stored(client).get_decoded()["more"] == "data"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (USER_AGENT, USER_AGENT),
        (
            "  Mozilla/5.0\x00\x1b[31m (X11)\r\n\tFirefox  ",
            "Mozilla/5.0 [31m (X11) Firefox",
        ),
        ("Bad\u2028line\u200bbreaks", "Bad line breaks"),
        ("x" * 513, "x" * 512),
        ("\x00\r\n ", None),
        ("", None),
        (None, None),
    ],
)
def test_user_agent_is_sanitized(value: str | None, expected: str | None) -> None:
    assert _clean_user_agent(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("198.51.100.7", "198.51.100.7"),
        ("2001:DB8:0:0::1", "2001:db8::1"),
        ("::ffff:198.51.100.7", "198.51.100.7"),
        ("fe80::1%eth0", "fe80::1"),
        (" 198.51.100.7 ", "198.51.100.7"),
        ("198.51.100.7, 10.0.0.1", None),
        ("unknown", None),
        ("", None),
        (None, None),
    ],
)
def test_ip_is_normalized(value: str | None, expected: str | None) -> None:
    assert _clean_ip(value) == expected


class TestLastActivity:
    def test_updates_at_most_once_per_interval(self, google: FakeGoogle) -> None:
        with time_machine.travel(T0, tick=False) as clock:
            client = browser()
            sign_in(client, google)
            assert stored(client).last_activity == T0

            clock.shift(59)
            with CaptureQueriesContext(connection) as queries:
                assert whoami(client)["authenticated"] is True
            assert not [q for q in queries if q["sql"].startswith("UPDATE")]
            assert stored(client).last_activity == T0

            clock.shift(1)
            whoami(client)
            assert stored(client).last_activity == T0 + timedelta(seconds=60)

            clock.shift(30)
            whoami(client)
            assert stored(client).last_activity == T0 + timedelta(seconds=60)

    def test_activity_update_records_the_new_device(self, google: FakeGoogle) -> None:
        with time_machine.travel(T0, tick=False) as clock:
            client = browser()
            sign_in(client, google)

            clock.shift(120)
            client.get("/", headers={"User-Agent": "Phone"}, REMOTE_ADDR="::1")

            session = stored(client)
            assert session.last_activity == T0 + timedelta(seconds=120)
            assert (session.user_agent, session.ip) == ("Phone", "::1")
            # Activity alone does not move the start of the session.
            assert session.created_at == T0

    def test_saving_the_session_records_activity(self, google: FakeGoogle) -> None:
        with time_machine.travel(T0, tick=False) as clock:
            client = browser()
            sign_in(client, google)

            before = stored(client)

            clock.shift(10)
            csrf_post(client, "/remember/")

            session = stored(client)
            assert session.last_activity == T0 + timedelta(seconds=10)
            # Saves keep what only an insert sets.
            assert (session.public_id, session.created_at) == (
                before.public_id,
                T0,
            )

    def test_requests_that_do_not_use_the_session_write_nothing(
        self, google: FakeGoogle
    ) -> None:
        with time_machine.travel(T0, tick=False) as clock:
            client = browser()
            sign_in(client, google)

            clock.shift(3600)
            with CaptureQueriesContext(connection) as queries:
                assert client.get("/missing/").status_code == 404

            assert not [q for q in queries if "cross_auth_session" in q["sql"]]

    def test_interval_is_a_setting(self, google: FakeGoogle) -> None:
        cross_auth = {**settings.CROSS_AUTH, "SESSION_ACTIVITY_INTERVAL": 0}
        with (
            override_settings(CROSS_AUTH=cross_auth),
            time_machine.travel(T0, tick=False) as clock,
        ):
            client = browser()
            sign_in(client, google)

            clock.shift(1)
            whoami(client)

            assert stored(client).last_activity == T0 + timedelta(seconds=1)


class TestListing:
    def test_lists_own_active_sessions_newest_first(self, google: FakeGoogle) -> None:
        user = password_user()
        other = make_user("other@example.com", password="secret")
        with time_machine.travel(T0, tick=False) as clock:
            phone = browser(user_agent="Phone", ip="198.51.100.1")
            sign_in(phone, google)
            clock.shift(60)
            old = browser(user_agent="Old")
            sign_in(old, google)
            expire(old)
            clock.shift(60)
            laptop = browser(user_agent="Laptop")
            password_login(laptop, "person@gmail.com")
            someone_else = browser(user_agent="Someone else")
            password_login(someone_else, "other@example.com")
            anonymous = browser(user_agent="Anonymous")
            csrf_post(anonymous, "/remember/")

            sessions = listed(laptop)

        assert [
            (s["user_agent"], s["login_method"], s["is_current"]) for s in sessions
        ] == [("Laptop", None, True), ("Phone", "google", False)]
        phone_row = stored(phone)
        assert sessions[1] == {
            "id": str(phone_row.public_id),
            "login_method": "google",
            "user_agent": "Phone",
            "ip": "198.51.100.1",
            "created_at": "2026-10-30T12:00:00Z",
            "last_activity": "2026-10-30T12:00:00Z",
            "expires_at": phone_row.expire_date.isoformat().replace("+00:00", "Z"),
            "is_current": False,
        }
        assert Session.objects.filter(user=user).count() == 3
        assert [s["user_agent"] for s in listed(someone_else)] == ["Someone else"]
        assert Session.objects.get(user=other).user_agent == "Someone else"

    def test_session_keys_are_never_listed(self, google: FakeGoogle) -> None:
        password_user()
        phone, laptop = browser(), browser()
        sign_in(phone, google)
        sign_in(laptop, google)

        body = laptop.get("/sessions/").content.decode()

        for client in (phone, laptop):
            assert client.cookies[settings.SESSION_COOKIE_NAME].value not in body

    def test_anonymous_request_lists_nothing(self) -> None:
        client = browser()
        csrf_post(client, "/remember/")

        assert listed(client) == []

    def test_sessions_a_password_change_ended_are_not_listed(self) -> None:
        make_user("person@example.com", password="secret")
        phone, laptop = browser(user_agent="Phone"), browser(user_agent="Laptop")
        password_login(phone, "person@example.com")
        password_login(laptop, "person@example.com")

        response = csrf_post(
            laptop,
            "/accounts/password_change/",
            {
                "old_password": "secret",
                "new_password1": "a new password",
                "new_password2": "a new password",
            },
        )

        assert response.status_code == 302
        # Django keeps the laptop signed in and logs the phone out on its next
        # request; until then its row is still there.
        assert [s["user_agent"] for s in listed(laptop)] == ["Laptop"]
        assert Session.objects.filter(user_agent="Phone").exists()
        assert whoami(phone)["authenticated"] is False

    @override_settings(SESSION_ENGINE="django.contrib.sessions.backends.db")
    def test_needs_the_engine(self) -> None:
        client = Client(raise_request_exception=True)

        with pytest.raises(ImproperlyConfigured, match="cross_auth.django.sessions"):
            client.get("/sessions/")


class TestRevoking:
    def test_revokes_one_of_the_users_sessions(self, google: FakeGoogle) -> None:
        password_user()
        phone, laptop = browser(), browser()
        sign_in(phone, google)
        sign_in(laptop, google)

        response = csrf_post(laptop, "/sessions/", {"id": str(stored(phone).public_id)})

        assert response.json() == {"revoked": True}
        assert whoami(phone)["authenticated"] is False
        assert whoami(laptop)["authenticated"] is True
        assert Session.objects.filter(user__isnull=False).count() == 1

    def test_never_revokes_another_users_session(self, google: FakeGoogle) -> None:
        password_user()
        make_user("other@example.com", password="secret")
        mine, theirs = browser(), browser()
        sign_in(mine, google)
        password_login(theirs, "other@example.com")
        their_id = str(stored(theirs).public_id)

        assert csrf_post(mine, "/sessions/", {"id": their_id}).json() == {
            "revoked": False
        }
        assert whoami(theirs)["authenticated"] is True

        anonymous = browser()
        assert csrf_post(anonymous, "/sessions/", {"id": their_id}).json() == {
            "revoked": False
        }
        assert whoami(theirs)["authenticated"] is True

    @pytest.mark.parametrize(
        "session_id", ["not-a-uuid", "", "00000000-0000-0000-0000-000000000000"]
    )
    def test_unknown_ids_revoke_nothing(
        self, google: FakeGoogle, session_id: str
    ) -> None:
        client = browser()
        sign_in(client, google)

        assert csrf_post(client, "/sessions/", {"id": session_id}).json() == {
            "revoked": False
        }
        assert whoami(client)["authenticated"] is True

    def test_revoking_the_current_session_logs_out(self, google: FakeGoogle) -> None:
        client = browser()
        sign_in(client, google)

        response = csrf_post(
            client, "/sessions/", {"id": str(stored(client).public_id)}
        )

        assert response.json() == {"revoked": True}
        assert response.cookies[settings.SESSION_COOKIE_NAME].value == ""
        assert whoami(client)["authenticated"] is False
        assert not Session.objects.exists()

    def test_revokes_the_other_sessions(self, google: FakeGoogle) -> None:
        password_user()
        make_user("other@example.com", password="secret")
        current, phone, tablet, old = browser(), browser(), browser(), browser()
        for client in (current, phone, tablet, old):
            sign_in(client, google)
        expire(old)
        theirs = browser()
        password_login(theirs, "other@example.com")

        response = csrf_post(current, "/sessions/")

        assert response.json() == {"revoked": 2}
        assert whoami(current)["authenticated"] is True
        assert whoami(phone)["authenticated"] is False
        assert whoami(tablet)["authenticated"] is False
        assert whoami(theirs)["authenticated"] is True
        # Expired sessions are left for clearsessions.
        assert Session.objects.filter(pk=stored(old).pk).exists()

    def test_anonymous_request_revokes_nothing(self, google: FakeGoogle) -> None:
        signed_in = browser()
        sign_in(signed_in, google)

        assert csrf_post(browser(), "/sessions/").json() == {"revoked": 0}
        assert whoami(signed_in)["authenticated"] is True


class TestLifecycle:
    def test_clearsessions_deletes_expired_sessions(self, google: FakeGoogle) -> None:
        active, expired = browser(), browser()
        sign_in(active, google)
        sign_in(expired, google)
        expire(expired)

        call_command("clearsessions")

        assert list(Session.objects.values_list("pk", flat=True)) == [stored(active).pk]

    def test_logout_deletes_the_session(self, google: FakeGoogle) -> None:
        client = browser()
        sign_in(client, google)

        csrf_post(client, "/accounts/logout/")

        assert whoami(client)["authenticated"] is False
        assert not Session.objects.exists()

    def test_login_rotates_the_key_without_leaving_rows(
        self, google: FakeGoogle
    ) -> None:
        client = browser()
        csrf_post(client, "/remember/")
        anonymous = stored(client)

        sign_in(client, google)

        session = stored(client)
        assert session.session_key != anonymous.session_key
        assert session.public_id != anonymous.public_id
        assert session.get_decoded()["remembered"] == "yes"
        assert list(Session.objects.all()) == [session]

        # Another user in the same browser: Django flushes the session.
        other = make_user("other@example.com", password="secret")
        password_login(client, "other@example.com")

        session = stored(client)
        assert session.user_id == other.pk
        assert "remembered" not in session.get_decoded()
        assert list(Session.objects.all()) == [session]

    def test_password_change_rotates_the_key_without_leaving_rows(self) -> None:
        make_user("person@example.com", password="secret")
        client = browser()
        password_login(client, "person@example.com")
        before = stored(client)

        csrf_post(
            client,
            "/accounts/password_change/",
            {
                "old_password": "secret",
                "new_password1": "a new password",
                "new_password2": "a new password",
            },
        )

        assert whoami(client)["authenticated"] is True
        assert stored(client).session_key != before.session_key
        assert Session.objects.count() == 1

    def test_deleting_a_user_deletes_their_sessions(self, google: FakeGoogle) -> None:
        client = browser()
        sign_in(client, google)
        user = stored(client).user
        assert user is not None

        user.delete()

        assert not Session.objects.exists()


class TestStore:
    def test_session_of_a_missing_user_fails_instead_of_retrying(self) -> None:
        user = make_user("gone@example.com")
        user_id = str(user.pk)
        user.delete()
        store = SessionStore()
        store[SESSION_KEY] = user_id
        store[BACKEND_SESSION_KEY] = BACKEND

        with pytest.raises(IntegrityError):
            store.save()

        assert not Session.objects.exists()

    def test_async_login_fills_the_columns(self) -> None:
        user = make_user("person@example.com")
        request = RequestFactory().get("/")
        store = SessionStore()
        store.set_client(user_agent=USER_AGENT, ip=IP)
        request.session = store

        async def login() -> dict[str, Any]:
            await alogin(request, user, backend=BACKEND)
            await store.aset(LOGIN_METHOD_SESSION_KEY, "google")
            await store.asave()
            assert store.session_key is not None
            return await SessionStore(store.session_key).aload()

        data = async_to_sync(login)()

        session = Session.objects.get()
        assert session.user_id == user.pk
        assert session.login_method == "google"
        assert (session.user_agent, session.ip) == (USER_AGENT, IP)
        assert data[SESSION_KEY] == str(user.pk)

    def test_login_method_needs_cross_auths_backend(self) -> None:
        store = SessionStore()
        store[LOGIN_METHOD_SESSION_KEY] = "google"
        store[BACKEND_SESSION_KEY] = PASSWORD_BACKEND

        assert store.create_model_instance(dict(store.items())).login_method is None
