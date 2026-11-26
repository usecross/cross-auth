"""Two-factor authentication on Django, through real requests and middleware.

Django's own logins (``LoginView`` here, the admin's is the same view) are
held back by the ``user_logged_in`` guard; provider sign-ins by core.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
from asgiref.sync import async_to_sync
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.base_user import AbstractBaseUser
from django.dispatch import Signal
from django.test import AsyncClient, Client, override_settings
from django.utils import timezone as django_timezone

from cross_auth import _totp
from cross_auth._mfa import _Cipher, hash_recovery_code
from cross_auth.django import signals
from cross_auth.django.checks import check_mfa_setup, check_settings
from cross_auth.django.models import MFAFactor, RecoveryCode, Session
from cross_auth.django.storage import DjangoMFAStorage
from cross_auth.django.test import login_with_mfa
from cross_auth.django.views import mfa_secret_keys

from . import settings as test_settings
from .fake_google import Account, FakeGoogle
from .support import connect, csrf_post, sign_in, whoami

pytestmark = pytest.mark.django_db(transaction=True)

SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
PASSWORD = "correct horse battery staple"
MFA_MIDDLEWARE = [
    "cross_auth.django.sessions.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "cross_auth.django.mfa.MFAMiddleware",
]


def _mfa_settings(**mfa: Any) -> override_settings:
    return override_settings(
        CROSS_AUTH={**settings.CROSS_AUTH, "MFA": {"issuer": "Acme", **mfa}},
        SESSION_ENGINE="cross_auth.django.sessions",
        MIDDLEWARE=MFA_MIDDLEWARE,
    )


@pytest.fixture(autouse=True)
def mfa_on() -> Iterator[None]:
    with _mfa_settings():
        yield


@pytest.fixture
def client() -> Client:
    return Client(enforce_csrf_checks=True)


@pytest.fixture
def received() -> Iterator[list[tuple[str, dict[str, Any]]]]:
    events: list[tuple[str, dict[str, Any]]] = []
    connected: list[tuple[Signal, Any]] = []
    for name in (
        "mfa_verified",
        "mfa_verification_failed",
        "mfa_factor_added",
        "recovery_code_used",
    ):
        signal: Signal = getattr(signals, name)

        def receiver(sender: object, _name: str = name, **kwargs: Any) -> None:
            events.append((_name, kwargs))

        signal.connect(receiver, weak=False)
        connected.append((signal, receiver))
    yield events
    for signal, receiver in connected:
        signal.disconnect(receiver)


def make_user(email: str = "person@example.com") -> AbstractBaseUser:
    from .support import make_user as make

    return make(email, password=PASSWORD)


def add_totp(user: AbstractBaseUser, *, codes: list[str] | None = None) -> None:
    """Give ``user`` an authenticator on SECRET, as a finished enrollment does."""
    cipher = _Cipher({"secret_keys": mfa_secret_keys()})
    store = DjangoMFAStorage()
    now = datetime.now(tz=timezone.utc)
    store.create_factor(
        user_id=user.pk,
        type="totp",
        name="Phone",
        data={"secret": cipher.encrypt(SECRET)},
        created_at=now,
        recovery_code_hashes=[hash_recovery_code(c) for c in codes or []],
    )


def code(secret: str = SECRET) -> str:
    return _totp.code_at(secret, _totp.time_step(datetime.now(tz=timezone.utc)))


def password_login(
    client: Client, next_url: str = "/private/", email: str = "person@example.com"
) -> Any:
    return csrf_post(
        client,
        f"/accounts/login/?next={next_url}",
        {"username": email, "password": PASSWORD},
    )


def stored_sessions() -> list[Session]:
    return list(Session.objects.filter(token_hash__isnull=True))


def test_password_login_waits_for_the_code(
    client: Client, received: list[tuple[str, dict[str, Any]]]
) -> None:
    user = make_user()
    add_totp(user)

    response = password_login(client)

    assert response.status_code == 303
    location = urlparse(response["Location"])
    assert location.path == "/auth/mfa/verify"
    assert parse_qs(location.query) == {"next": ["/private/"]}
    assert response.cookies["mfa_challenge"]["httponly"]
    # The session was saved, but never with the user in it.
    assert [s.user_id for s in stored_sessions()] == [None]
    assert whoami(client)["authenticated"] is False
    user.refresh_from_db()
    assert user.last_login is None

    page = client.get(response["Location"])
    assert page.status_code == 200
    assert b'name="code"' in page.content

    wrong = csrf_post(
        client, "/auth/mfa/verify", {"code": "000000", "next": "/private/"}
    )
    assert wrong.status_code == 400
    assert b"not correct" in wrong.content
    assert whoami(client)["authenticated"] is False

    verified = csrf_post(
        client, "/auth/mfa/verify", {"code": code(), "next": "/private/"}
    )

    assert verified.status_code == 303
    assert verified["Location"] == "/private/"
    me = whoami(client)
    assert me == {
        "authenticated": True,
        "user_id": str(user.pk),
        "backend": "django.contrib.auth.backends.ModelBackend",
    }
    [session] = stored_sessions()
    assert session.user_id == user.pk and session.mfa_method == "totp"
    user.refresh_from_db()
    assert user.last_login is not None
    assert [name for name, _ in received] == ["mfa_verification_failed", "mfa_verified"]
    assert received[1][1]["method"] == "totp"
    assert client.get("/verified/").status_code == 200


def test_an_app_can_draw_its_own_verify_page(google: FakeGoogle) -> None:
    user = make_user("person@gmail.com")
    connect(user)
    add_totp(user, codes=["aaaa-bbbb"])

    with _mfa_settings(verify_url="own_verify"):
        client = Client(enforce_csrf_checks=True)
        waiting = password_login(client, email="person@gmail.com")
        assert waiting["Location"] == "/sign-in/code/?next=%2Fprivate%2F"
        page = client.get(waiting["Location"]).json()
        assert page == {
            "methods": ["totp", "recovery_code"],
            "error": None,
            "next": "/private/",
        }
        # The library's page sends browsers to the app's, keeping the query.
        assert client.get("/auth/mfa/verify?next=/private/")["Location"] == (
            "/sign-in/code/?next=/private/"
        )

        wrong = csrf_post(
            client, "/auth/mfa/verify", {"code": "000000", "next": "/private/"}
        )
        assert wrong.status_code == 303
        assert (
            wrong["Location"] == "/sign-in/code/?error=invalid_code&next=%2Fprivate%2F"
        )
        verified = csrf_post(
            client, "/auth/mfa/verify", {"code": code(), "next": "/private/"}
        )
        assert verified["Location"] == "/private/"
        assert whoami(client)["user_id"] == str(user.pk)
        assert client.get("/sign-in/code/").json()["methods"] is None

        # Provider sign-ins are sent there too, by core.
        other = Client(enforce_csrf_checks=True)
        response = sign_in(other, google, Account(email="person@gmail.com"))
        assert response["Location"] == "/sign-in/code/"


def test_a_user_without_a_factor_logs_in_at_once(client: Client) -> None:
    user = make_user()

    response = password_login(client)

    assert response.status_code == 302
    assert response["Location"] == "/private/"
    assert whoami(client)["user_id"] == str(user.pk)
    # Signed in without a second factor: mfa_required pages refuse it.
    assert client.get("/verified/").status_code == 302


def test_a_json_login_gets_mfa_required(client: Client) -> None:
    user = make_user()
    add_totp(user)

    response = csrf_post(
        client,
        "/api/login",
        {"username": "person@example.com", "password": PASSWORD},
    )
    # A form post navigates; a JSON client asks for JSON.
    assert response.status_code == 303

    client.get("/")
    response = client.post(
        "/api/login",
        {"username": "person@example.com", "password": PASSWORD},
        headers={
            "Accept": "application/json",
            "X-CSRFToken": client.cookies["csrftoken"].value,
        },
    )
    assert response.status_code == 401
    assert response.json() == {
        "error": "mfa_required",
        "error_description": "Two-factor authentication is required",
        "methods": ["totp"],
        "verify_url": "/auth/mfa/verify",
    }
    assert whoami(client)["authenticated"] is False


def test_a_recovery_code_works_once(
    client: Client, received: list[tuple[str, dict[str, Any]]]
) -> None:
    user = make_user()
    add_totp(user, codes=["abcde-fghjk", "mnpqr-stuvw"])

    password_login(client)
    response = csrf_post(client, "/auth/mfa/verify", {"recovery_code": "ABCDE FGHJK"})
    assert response.status_code == 303
    assert whoami(client)["user_id"] == str(user.pk)
    assert ("recovery_code_used", received[0][1]) == received[0]
    assert received[0][1]["remaining"] == 1

    other = Client(enforce_csrf_checks=True)
    password_login(other)
    again = csrf_post(other, "/auth/mfa/verify", {"recovery_code": "abcde-fghjk"})
    assert again.status_code == 400
    assert whoami(other)["authenticated"] is False
    assert RecoveryCode.objects.filter(used_at__isnull=True).count() == 1


def test_a_code_cannot_be_used_twice(client: Client) -> None:
    user = make_user()
    add_totp(user)
    current = code()

    password_login(client)
    assert csrf_post(client, "/auth/mfa/verify", {"code": current}).status_code == 303

    other = Client(enforce_csrf_checks=True)
    password_login(other)
    assert csrf_post(other, "/auth/mfa/verify", {"code": current}).status_code == 400
    assert whoami(other)["authenticated"] is False
    del user


def test_a_password_change_ends_the_waiting_login(client: Client) -> None:
    user = make_user()
    add_totp(user)
    password_login(client)

    user.set_password("another password")
    user.save()

    response = csrf_post(client, "/auth/mfa/verify", {"code": code()})
    assert response.status_code == 400
    assert whoami(client)["authenticated"] is False


def test_signing_out_other_sessions_ends_a_login_waiting_for_its_code(
    client: Client,
) -> None:
    """The intruder knows the password and has no session yet, only the
    challenge: signing out everywhere else must stop it too."""
    user = make_user()
    add_totp(user)
    login_with_mfa(client, user)
    intruder = Client(enforce_csrf_checks=True)
    assert password_login(intruder).status_code == 303

    assert csrf_post(client, "/sessions/").json() == {"revoked": 0}

    response = csrf_post(intruder, "/auth/mfa/verify", {"code": code()})
    assert response.status_code == 400
    assert whoami(intruder)["authenticated"] is False


def test_a_login_refused_while_waiting_for_its_code_gets_the_refusal(
    client: Client,
) -> None:
    """The account is deactivated after its password passed. The rule Cross
    Auth asks returns its refusal, which the verify view answers with."""
    user = make_user()
    add_totp(user)
    password_login(client)
    get_user_model().objects.filter(pk=user.pk).update(is_active=False)

    response = client.post(
        "/auth/mfa/verify",
        {"code": code()},
        headers={
            "Accept": "application/json",
            "X-CSRFToken": client.cookies["csrftoken"].value,
        },
    )

    assert response.status_code == 403
    assert response.json() == {
        "error": "access_denied",
        "error_description": "This account is inactive.",
    }
    assert whoami(client)["authenticated"] is False
    assert all(session.user_id is None for session in stored_sessions())


def test_wrong_codes_lock_the_account(client: Client) -> None:
    user = make_user()
    add_totp(user)
    # Two sign-ins of five attempts each reach the account's limit of ten.
    for _ in range(2):
        password_login(client)
        for _ in range(5):
            csrf_post(client, "/auth/mfa/verify", {"code": "000000"})

    password_login(client)
    locked = csrf_post(client, "/auth/mfa/verify", {"code": code()})
    assert locked.status_code == 429
    assert whoami(client)["authenticated"] is False
    factor = MFAFactor.objects.get(user=user)
    assert factor.locked_until is not None


def test_provider_sign_in_waits_for_the_code(
    client: Client, google: FakeGoogle
) -> None:
    user = make_user("person@gmail.com")
    connect(user)
    add_totp(user)

    response = sign_in(client, google, Account(email="person@gmail.com"))

    assert response.status_code == 302
    assert response["Location"] == "/auth/mfa/verify"
    assert whoami(client)["authenticated"] is False
    assert all(s.user_id is None for s in stored_sessions())

    verified = csrf_post(client, "/auth/mfa/verify", {"code": code()})
    assert verified.status_code == 302
    assert verified["Location"] == "/"
    me = whoami(client)
    assert me["user_id"] == str(user.pk)
    assert me["backend"] == "cross_auth.django.backends.CrossAuthBackend"
    [session] = stored_sessions()
    assert (session.login_method, session.mfa_method) == ("google", "totp")


def test_apps_can_skip_2fa_for_provider_sign_ins(
    client: Client, google: FakeGoogle
) -> None:
    user = make_user("person@gmail.com")
    connect(user)
    add_totp(user)

    with _mfa_settings(require_for_providers=False):
        response = sign_in(client, google, Account(email="person@gmail.com"))
        assert response.status_code == 302
        assert response["Location"] == "/"
        assert whoami(client)["user_id"] == str(user.pk)
        # Passwords are still challenged.
        other = Client(enforce_csrf_checks=True)
        assert password_login(other, email="person@gmail.com").status_code == 303
        assert whoami(other)["authenticated"] is False


def test_turning_on_2fa(
    client: Client, received: list[tuple[str, dict[str, Any]]]
) -> None:
    user = make_user()
    connect(user)  # a provider verified person@example.com
    other = Client()
    other.force_login(user)
    password_login(client)
    assert whoami(client)["user_id"] == str(user.pk)
    token = client.cookies["csrftoken"].value
    headers = {"X-CSRFToken": token}

    started = client.post(
        "/auth/mfa/totp/enroll",
        {"name": "Phone"},
        content_type="application/json",
        headers=headers,
    )
    assert started.status_code == 200, started.content
    enrollment = started.json()
    assert enrollment["otpauth_uri"].startswith("otpauth://totp/Acme:person")
    assert not MFAFactor.objects.exists()

    first_code = code(enrollment["secret"])
    confirmed = client.post(
        "/auth/mfa/totp/confirm",
        {"enrollment_id": enrollment["enrollment_id"], "code": first_code},
        content_type="application/json",
        headers=headers,
    )
    assert confirmed.status_code == 201, confirmed.content
    body = confirmed.json()
    assert body["factor"]["name"] == "Phone"
    assert len(body["recovery_codes"]) == 10
    assert RecoveryCode.objects.filter(user=user).count() == 10
    # Codes are stored hashed only.
    assert not RecoveryCode.objects.filter(
        code_hash__in=body["recovery_codes"]
    ).exists()
    assert [name for name, _ in received] == ["mfa_factor_added"]
    assert received[0][1]["enabled_mfa"] is True

    # The other session is signed out; this one stays.
    assert whoami(other)["authenticated"] is False
    assert whoami(client)["user_id"] == str(user.pk)

    status = client.get("/auth/mfa").json()
    assert status["enabled"] is True
    assert status["recovery_codes_remaining"] == 10


def test_2fa_changes_need_a_recent_sign_in(client: Client) -> None:
    user = make_user()
    add_totp(user)
    login_with_mfa(client, user)
    Session.objects.update(created_at=django_timezone.now() - timedelta(minutes=10))
    client.get("/")
    headers = {"X-CSRFToken": client.cookies["csrftoken"].value}
    factor = MFAFactor.objects.get()

    refused = client.post(
        f"/auth/mfa/factors/{factor.pk}/remove",
        content_type="application/json",
        headers=headers,
    )
    assert refused.status_code == 403
    assert refused.json()["error"] == "reauthentication_required"
    assert refused.json()["methods"] == ["password", "totp", "sign_in_again"]
    assert MFAFactor.objects.exists()

    wrong = client.post(
        "/auth/reauthenticate",
        {"password": "wrong"},
        content_type="application/json",
        headers=headers,
    )
    assert wrong.status_code == 400
    ok = client.post(
        "/auth/reauthenticate",
        {"password": PASSWORD},
        content_type="application/json",
        headers=headers,
    )
    assert ok.status_code == 200, ok.content

    removed = client.post(
        f"/auth/mfa/factors/{factor.pk}/remove",
        content_type="application/json",
        headers=headers,
    )
    assert removed.status_code == 200
    assert removed.json() == {
        "enabled": False,
        "factors": [],
        "recovery_codes_remaining": 0,
    }


def test_a_device_logins_session_must_reauthenticate_before_changing_2fa(
    client: Client,
) -> None:
    """The device was approved from another session: signing in proved
    nothing in this one, so only reauthenticating in it counts."""
    user = make_user()
    add_totp(user)
    login_with_mfa(client, user)
    client.get("/")
    headers = {"X-CSRFToken": client.cookies["csrftoken"].value}
    # A fresh sign-in counts as recent.
    assert client.get("/recent/").status_code == 200

    Session.objects.update(login_method="device")

    refused = client.post(
        "/auth/mfa/recovery-codes", content_type="application/json", headers=headers
    )
    assert refused.status_code == 403
    assert refused.json()["error"] == "reauthentication_required"
    assert client.get("/recent/")["Location"] == "/confirm-identity/?next=/recent/"

    confirmed = client.post(
        "/auth/reauthenticate",
        {"password": PASSWORD},
        content_type="application/json",
        headers=headers,
    )
    assert confirmed.status_code == 200, confirmed.content
    assert client.get("/recent/").status_code == 200
    allowed = client.post(
        "/auth/mfa/recovery-codes", content_type="application/json", headers=headers
    )
    assert allowed.status_code == 200, allowed.content


def test_force_login_leaves_a_user_with_2fa_anonymous() -> None:
    user = make_user()
    add_totp(user)
    client = Client()

    client.force_login(user)
    assert whoami(client)["authenticated"] is False

    login_with_mfa(client, user)
    assert whoami(client)["user_id"] == str(user.pk)
    assert client.get("/verified/").status_code == 200


def test_enrolling_needs_a_verified_email(client: Client) -> None:
    user = make_user()
    login_with_mfa(client, user)
    client.get("/")
    response = client.post(
        "/auth/mfa/totp/enroll",
        content_type="application/json",
        headers={"X-CSRFToken": client.cookies["csrftoken"].value},
    )
    assert response.status_code == 400
    assert response.json()["error"] == "email_not_verified"


def test_requires_mfa_refuses_staff_without_a_factor(client: Client) -> None:
    make_user()
    with _mfa_settings(requires_mfa="tests.django.test_mfa.everyone"):
        response = password_login(client)
    assert response.status_code == 303
    assert response["Location"] == "/auth/mfa/verify?error=mfa_enrollment_required"
    assert whoami(client)["authenticated"] is False


def everyone(user: AbstractBaseUser, login_method: str | None) -> bool:
    return True


def test_views_are_not_found_without_mfa(client: Client) -> None:
    with override_settings(CROSS_AUTH=test_settings.CROSS_AUTH):
        assert client.get("/auth/mfa").status_code == 404


def test_checks_require_the_middleware_and_session_engine() -> None:
    with override_settings(
        MIDDLEWARE=[m for m in MFA_MIDDLEWARE if "mfa" not in m],
        SESSION_ENGINE="django.contrib.sessions.backends.db",
    ):
        ids = {message.id for message in check_mfa_setup()}
    assert {"cross_auth.E006", "cross_auth.E008"} <= ids
    assert not {"cross_auth.E006", "cross_auth.E008"} & {
        message.id for message in check_mfa_setup()
    }


def test_bad_mfa_settings_are_reported() -> None:
    with _mfa_settings(max_attempts=0, encrypt="tests.django.token_crypto.encrypt"):
        messages = [m for m in check_settings() if m.id == "cross_auth.E001"]
    assert "both 'encrypt' and 'decrypt'" in messages[0].msg


def test_an_async_login_waits_for_the_code() -> None:
    user = make_user()
    add_totp(user)
    client = AsyncClient()

    response = async_to_sync(client.post)(
        "/async-login", {"username": "person@example.com", "password": PASSWORD}
    )

    assert response.status_code == 303
    assert response["Location"] == "/auth/mfa/verify?next=%2Fprivate%2F"
    assert [s.user_id for s in stored_sessions()] == [None]


def test_a_new_login_drops_the_last_sessions_second_factor(client: Client) -> None:
    """A login that passed no second factor never inherits an earlier one's."""
    first = make_user()
    add_totp(first)
    make_user("other@example.com")
    password_login(client)
    csrf_post(client, "/auth/mfa/verify", {"code": code(), "next": "/private/"})
    assert client.get("/verified/").status_code == 200

    # The first user's next login waits for a code and takes them out of the
    # session; the second user, who has no factor, then logs in straight away.
    assert password_login(client)["Location"].startswith("/auth/mfa/verify")
    assert password_login(client, email="other@example.com")["Location"] == (
        "/private/"
    )

    assert whoami(client)["authenticated"] is True
    assert client.get("/verified/").status_code != 200


def test_verify_works_with_atomic_requests(
    client: Client, google: FakeGoogle, monkeypatch: pytest.MonkeyPatch
) -> None:
    from django.db import connections

    user = make_user("person@gmail.com")
    connect(user)
    add_totp(user)
    assert sign_in(client, google, Account(email="person@gmail.com")).status_code
    monkeypatch.setitem(connections["default"].settings_dict, "ATOMIC_REQUESTS", True)

    verified = csrf_post(client, "/auth/mfa/verify", {"code": code()})

    assert verified.status_code == 302
    assert whoami(client)["user_id"] == str(user.pk)
