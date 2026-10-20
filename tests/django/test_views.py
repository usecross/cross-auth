"""Browser flows through Django's test client with CSRF checks enforced.

Views run as real requests through Django's middleware with committed
transactions (``transaction=True``); only Google's network is faked.
"""

from __future__ import annotations

import re
import threading
import uuid
from collections.abc import Callable, Iterator
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
import respx
from asgiref.sync import async_to_sync
from django.apps import apps
from django.conf import settings
from django.contrib.auth import get_user_model, user_logged_in
from django.contrib.auth.models import Permission, PermissionsMixin
from django.contrib.sessions.models import Session
from django.core.exceptions import PermissionDenied
from django.db import IntegrityError, connections, transaction
from django.http import HttpRequest, HttpResponse, HttpResponseBase
from django.test import AsyncClient, Client, RequestFactory, override_settings

from cross_auth._auth_flow import _create_social_account
from cross_auth._context import Context
from cross_auth.django import views
from cross_auth.django.conf import get_settings
from cross_auth.django.models import ExpiringValue, SocialAccount
from cross_auth.django.storage import (
    DjangoAccountsStorage,
    DjangoSecondaryStorage,
    DjangoUser,
)

from .conftest import CUSTOM_USER, connect, make_user
from .fake_google import CALLBACK, Account, Authorization, FakeGoogle
from .testapp import signals

pytestmark = pytest.mark.django_db(transaction=True)

BACKEND = "cross_auth.django.backends.CrossAuthBackend"


@pytest.fixture
def google() -> Iterator[FakeGoogle]:
    with respx.mock(assert_all_called=False) as router:
        fake = FakeGoogle(router)
        fake.install()
        yield fake


@pytest.fixture(autouse=True)
def reset_signals() -> Iterator[None]:
    signals.events.clear()
    signals.handlers.clear()
    yield
    signals.events.clear()
    signals.handlers.clear()


def sent() -> list[str]:
    return [name for name, _ in signals.events]


def payload(name: str) -> dict[str, Any]:
    [kwargs] = [kwargs for sent_name, kwargs in signals.events if sent_name == name]
    return kwargs


@pytest.fixture
def client() -> Client:
    return Client(enforce_csrf_checks=True)


def csrf_post(client: Client, path: str, data: dict[str, str] | None = None) -> Any:
    if "csrftoken" not in client.cookies:
        client.get("/")
    token = client.cookies["csrftoken"].value
    return client.post(path, {**(data or {}), "csrfmiddlewaretoken": token})


def whoami(client: Client) -> dict[str, Any]:
    return client.get("/").json()


def start_login(
    client: Client, google: FakeGoogle, next_url: str | None = None
) -> Authorization:
    data = {"next": next_url} if next_url is not None else {}
    return google.authorize(csrf_post(client, "/auth/google/login/", data))


def sign_in(
    client: Client, google: FakeGoogle, account: Account | None = None
) -> HttpResponseBase:
    return google.callback(client, start_login(client, google), account)


def error_of(response: HttpResponseBase) -> str:
    """Return the error code shown on Cross Auth's error page."""
    assert response.status_code >= 400, response.status_code
    assert isinstance(response, HttpResponse)
    match = re.search(r"<code>([a-z_]+)</code>", response.content.decode())
    assert match is not None, response.content
    return match.group(1)


class TestSignIn:
    def test_initiation_redirects_to_google_with_pkce_and_nonce(
        self, client: Client, google: FakeGoogle
    ) -> None:
        response = csrf_post(client, "/auth/google/login/")

        authorization = google.authorize(response)
        assert authorization.params["client_id"] == "test-client-id"
        assert authorization.params["redirect_uri"] == CALLBACK
        assert authorization.params["response_type"] == "code"
        assert authorization.params["scope"] == "openid email profile"
        assert authorization.params["code_challenge_method"] == "S256"
        assert authorization.params["nonce"]
        assert "client_secret" not in authorization.params
        binding = [name for name in response.cookies if name.startswith("cross_auth")]
        assert binding == [f"cross_auth_oauth_{authorization.state}"]
        assert response.cookies[binding[0]]["httponly"]
        assert response.cookies[binding[0]]["samesite"] == "Lax"
        assert "no-cache" in response["Cache-Control"]

    def test_initiation_requires_post_and_csrf(self, client: Client) -> None:
        assert client.get("/auth/google/login/").status_code == 405
        assert client.post("/auth/google/login/").status_code == 403
        assert client.get("/auth/google/callback", {"state": "x"}).status_code != 405
        # CsrfViewMiddleware refuses the POST before the view would.
        assert client.post("/auth/google/callback").status_code == 403

    def test_unknown_provider_is_not_found(self, client: Client) -> None:
        assert csrf_post(client, "/auth/github/login/").status_code == 404
        assert client.get("/auth/github/callback").status_code == 404

    def test_first_sign_in_creates_user_and_native_session(
        self, client: Client, google: FakeGoogle
    ) -> None:
        client.get("/")
        session = client.session
        session["cart"] = "kept"
        session.save()
        anonymous_key = session.session_key

        response = sign_in(client, google)

        assert response.status_code == 302
        assert response["Location"] == "/"
        me = whoami(client)
        assert me["authenticated"] is True
        assert me["backend"] == BACKEND
        user = get_user_model()._default_manager.get(pk=me["user_id"])
        assert not user.has_usable_password()
        assert user.is_active
        assert getattr(user, "is_staff", False) is False
        assert getattr(user, "is_superuser", False) is False
        account = SocialAccount.objects.get()
        assert (account.user_id, account.provider_user_id) == (user.pk, "google-sub-1")
        assert account.provider_email == "person@gmail.com"
        assert account.is_login_method
        # Django rotated the session key and kept the anonymous session's data.
        assert client.session.session_key != anonymous_key
        assert client.session["cart"] == "kept"
        assert not Session.objects.filter(session_key=anonymous_key).exists()
        assert client.get("/private/").content == b"private"

    @override_settings(SESSION_ENGINE="django.contrib.sessions.backends.cached_db")
    def test_cached_database_sessions(self, client: Client, google: FakeGoogle) -> None:
        sign_in(client, google)

        assert whoami(client)["backend"] == BACKEND
        assert Session.objects.filter(session_key=client.session.session_key).exists()

    def test_only_django_cookies_persist(
        self, client: Client, google: FakeGoogle
    ) -> None:
        response = sign_in(client, google)

        persistent = {
            name
            for name, morsel in response.cookies.items()
            if morsel.value and morsel["max-age"] != 0
        }
        assert persistent <= {settings.SESSION_COOKIE_NAME, settings.CSRF_COOKIE_NAME}
        binding = [name for name in response.cookies if name.startswith("cross_auth")]
        assert len(binding) == 1
        assert response.cookies[binding[0]]["max-age"] == 0
        assert response.cookies[binding[0]].value == ""

    def test_returning_user_signs_in_to_the_same_account(
        self, client: Client, google: FakeGoogle
    ) -> None:
        sign_in(client, google)
        first = whoami(client)["user_id"]
        csrf_post(client, "/accounts/logout/")
        assert whoami(client)["authenticated"] is False

        sign_in(client, google, Account(email="renamed@gmail.com"))

        assert whoami(client)["user_id"] == first
        assert get_user_model()._default_manager.count() == 1
        assert SocialAccount.objects.get().provider_email == "renamed@gmail.com"

    def test_permissions_are_native(self, client: Client, google: FakeGoogle) -> None:
        sign_in(client, google)
        user = get_user_model()._default_manager.get(pk=whoami(client)["user_id"])
        permission = Permission.objects.get(codename="view_socialaccount")
        assert isinstance(user, PermissionsMixin)
        user.user_permissions.add(permission)

        signed_in = client.get("/").wsgi_request.user
        assert isinstance(signed_in, PermissionsMixin)
        assert signed_in.has_perm("cross_auth.view_socialaccount")

    def test_password_change_ends_provider_sessions(
        self, client: Client, google: FakeGoogle
    ) -> None:
        sign_in(client, google)
        user = get_user_model()._default_manager.get(pk=whoami(client)["user_id"])

        user.set_password("new password")
        user.save()

        assert whoami(client)["authenticated"] is False

    def test_inactive_user_cannot_sign_in(
        self, client: Client, google: FakeGoogle
    ) -> None:
        user = make_user("person@example.com", is_active=False)
        connect(user)

        response = sign_in(client, google)

        assert response.status_code == 403
        assert error_of(response) == "access_denied"
        assert whoami(client)["authenticated"] is False

    def test_deactivated_user_loses_existing_session(
        self, client: Client, google: FakeGoogle
    ) -> None:
        sign_in(client, google)
        get_user_model()._default_manager.update(is_active=False)

        assert whoami(client)["authenticated"] is False

    def test_existing_email_is_not_linked_automatically(
        self, client: Client, google: FakeGoogle
    ) -> None:
        existing = make_user("person@gmail.com", password="secret")

        response = sign_in(client, google)

        assert error_of(response) == "account_not_linked"
        assert whoami(client)["authenticated"] is False
        assert not SocialAccount.objects.exists()
        assert get_user_model()._default_manager.get().pk == existing.pk

    def test_unverified_email_cannot_sign_up(
        self, client: Client, google: FakeGoogle
    ) -> None:
        response = sign_in(client, google, Account(email_verified=False))

        assert error_of(response) == "email_not_verified"
        assert not get_user_model()._default_manager.exists()

    def test_missing_email_cannot_sign_up(
        self, client: Client, google: FakeGoogle
    ) -> None:
        response = sign_in(client, google, Account(email=None, email_verified=None))

        assert response.status_code == 400
        assert not get_user_model()._default_manager.exists()

    def test_connection_only_identity_cannot_sign_in(
        self, client: Client, google: FakeGoogle
    ) -> None:
        connect(make_user("owner@example.com"), is_login_method=False)

        response = sign_in(client, google)

        assert error_of(response) == "access_denied"
        assert whoami(client)["authenticated"] is False

    def test_failed_token_exchange_creates_nothing(
        self, client: Client, google: FakeGoogle
    ) -> None:
        authorization = start_login(client, google)

        response = client.get(
            "/auth/google/callback", {"state": authorization.state, "code": "forged"}
        )

        assert response.status_code == 400
        assert whoami(client)["authenticated"] is False
        assert not get_user_model()._default_manager.exists()

    def test_wrong_nonce_is_rejected(self, client: Client, google: FakeGoogle) -> None:
        authorization = start_login(client, google)
        authorization.params["nonce"] = "attacker-nonce"

        response = google.callback(client, authorization)

        assert error_of(response) == "invalid_token"
        assert whoami(client)["authenticated"] is False

    def test_provider_denial_creates_nothing(
        self, client: Client, google: FakeGoogle
    ) -> None:
        authorization = start_login(client, google)

        response = client.get(
            "/auth/google/callback",
            {"state": authorization.state, "error": "access_denied"},
        )

        assert error_of(response) == "access_denied"
        assert not get_user_model()._default_manager.exists()


class TestCallbackBinding:
    def test_replayed_callback_is_rejected(
        self, client: Client, google: FakeGoogle
    ) -> None:
        authorization = start_login(client, google)
        code = google.approve(authorization, Account())
        params = {"state": authorization.state, "code": code}
        assert client.get("/auth/google/callback", params).status_code == 302
        csrf_post(client, "/accounts/logout/")

        response = client.get("/auth/google/callback", params)

        assert response.status_code >= 300
        assert whoami(client)["authenticated"] is False

    def test_other_browser_cannot_complete_the_flow(self, google: FakeGoogle) -> None:
        victim = Client(enforce_csrf_checks=True)
        attacker = Client(enforce_csrf_checks=True)
        authorization = start_login(victim, google)

        response = google.callback(attacker, authorization)

        assert error_of(response) == "invalid_request"
        assert whoami(attacker)["authenticated"] is False
        # The failed attempt did not consume the victim's flow.
        assert google.callback(victim, authorization).status_code == 302
        assert whoami(victim)["authenticated"] is True

    def test_callback_to_another_provider_is_rejected(
        self, client: Client, google: FakeGoogle
    ) -> None:
        authorization = start_login(client, google)

        response = google.callback(client, authorization, provider="workspace")

        assert error_of(response) == "server_error"
        assert whoami(client)["authenticated"] is False

    def test_concurrent_callbacks_complete_once(self, google: FakeGoogle) -> None:
        from .conftest import run_in_threads

        client = Client(enforce_csrf_checks=True)
        authorization = start_login(client, google)
        codes = [google.approve(authorization, Account()) for _ in range(3)]
        cookies = client.cookies

        def complete(index: int) -> str:
            browser = Client()
            browser.cookies = cookies
            response = browser.get(
                "/auth/google/callback",
                {"state": authorization.state, "code": codes[index]},
            )
            return response.get("Location", str(response.status_code))

        results = run_in_threads(3, complete)

        # One callback signs in; the others find the state already consumed
        # (400) or gone (redirect with an error).
        assert results.count("/") == 1, results
        assert all(
            result in {"/", "400"} or "error=session_expired" in str(result)
            for result in results
        ), results
        assert get_user_model()._default_manager.count() == 1
        assert sent().count("before_login") == 1

    def test_parallel_first_sign_ins_leave_one_user(
        self, google: FakeGoogle, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from .conftest import run_in_threads

        clients = [Client(enforce_csrf_checks=True) for _ in range(2)]
        authorizations = [start_login(client, google) for client in clients]
        codes = [
            google.approve(authorization, Account()) for authorization in authorizations
        ]
        # Both independent callbacks find no user before either creates one.
        found_none = threading.Barrier(2)
        find_user_by_email = DjangoAccountsStorage.find_user_by_email

        def find_then_wait(
            storage: DjangoAccountsStorage, email: str
        ) -> DjangoUser | None:
            user = find_user_by_email(storage, email)
            if user is None:
                found_none.wait(timeout=10)
            return user

        monkeypatch.setattr(DjangoAccountsStorage, "find_user_by_email", find_then_wait)

        def complete(index: int) -> HttpResponseBase:
            return clients[index].get(
                "/auth/google/callback",
                {"state": authorizations[index].state, "code": codes[index]},
            )

        results = run_in_threads(2, complete)
        monkeypatch.undo()

        responses = [result for result in results if isinstance(result, HttpResponse)]
        assert len(responses) == 2, results
        winner, loser = sorted(responses, key=lambda response: response.status_code)
        assert winner["Location"] == "/"
        assert error_of(loser) == "account_not_linked"
        native = get_user_model()._default_manager.get()
        assert SocialAccount.objects.get().user_id == native.pk
        assert sent().count("user_created") == 1
        assert sent().count("after_login") == 1

        # Signing in again from the losing browser reaches the same user.
        loser_client = clients[responses.index(loser)]
        assert sign_in(loser_client, google)["Location"] == "/"
        assert whoami(loser_client)["user_id"] == str(native.pk)
        assert get_user_model()._default_manager.count() == 1
        assert sent().count("user_created") == 1

    @pytest.mark.parametrize(
        ("next_url", "expected"),
        [
            ("/private/?tab=1", "/private/?tab=1"),
            ("//evil.example/", "/"),
            ("/\\evil.example/", "/"),
            ("https://evil.example/", "/"),
            ("http://testserver/private/", "/"),
            ("/\t/evil.example/", "/"),
            ("private/", "/"),
        ],
    )
    def test_next_must_be_a_safe_local_path(
        self, client: Client, google: FakeGoogle, next_url: str, expected: str
    ) -> None:
        authorization = start_login(client, google, next_url)

        response = google.callback(client, authorization)

        assert response["Location"] == expected


class TestLinking:
    def login_with_password(
        self, client: Client, email: str = "person@gmail.com"
    ) -> Any:
        user = make_user(email, password="secret")
        client.force_login(user, backend="django.contrib.auth.backends.ModelBackend")
        return user

    def test_password_user_links_google_and_signs_in_with_it(
        self, client: Client, google: FakeGoogle
    ) -> None:
        user = self.login_with_password(client)

        authorization = google.authorize(
            csrf_post(client, "/auth/google/link/", {"next": "/private/"})
        )
        response = google.callback(client, authorization)

        assert response["Location"] == "/private/"
        account = SocialAccount.objects.get()
        assert account.user_id == user.pk
        assert account.is_login_method
        # Linking leaves the existing session alone.
        assert whoami(client)["backend"] == "django.contrib.auth.backends.ModelBackend"

        csrf_post(client, "/accounts/logout/")
        sign_in(client, google)
        assert whoami(client)["user_id"] == str(user.pk)
        assert whoami(client)["backend"] == BACKEND

    def test_linking_requires_a_signed_in_user(
        self, client: Client, google: FakeGoogle
    ) -> None:
        response = csrf_post(client, "/auth/google/link/")

        assert response.status_code == 401
        assert client.get("/auth/google/link/").status_code == 405

    def test_link_requires_csrf(self, client: Client) -> None:
        self.login_with_password(client)

        assert client.post("/auth/google/link/").status_code == 403

    def test_link_rejects_a_different_user_at_callback(
        self, client: Client, google: FakeGoogle
    ) -> None:
        self.login_with_password(client)
        authorization = google.authorize(csrf_post(client, "/auth/google/link/"))
        other = make_user("other@gmail.com", password="secret")
        client.force_login(other, backend="django.contrib.auth.backends.ModelBackend")

        response = google.callback(client, authorization)

        assert response.status_code == 403
        assert not SocialAccount.objects.exists()

    def test_link_rejects_a_signed_out_browser(
        self, client: Client, google: FakeGoogle
    ) -> None:
        self.login_with_password(client)
        authorization = google.authorize(csrf_post(client, "/auth/google/link/"))
        csrf_post(client, "/accounts/logout/")

        response = google.callback(client, authorization)

        assert response.status_code == 403
        assert not SocialAccount.objects.exists()

    def test_identity_owned_by_someone_else_is_not_moved(
        self, client: Client, google: FakeGoogle
    ) -> None:
        owner = make_user("owner@example.com")
        connect(owner)
        self.login_with_password(client)

        authorization = google.authorize(csrf_post(client, "/auth/google/link/"))
        response = google.callback(client, authorization)

        assert error_of(response) == "account_already_linked"
        assert SocialAccount.objects.get().user_id == owner.pk

    def test_different_email_needs_explicit_setting(
        self, client: Client, google: FakeGoogle
    ) -> None:
        self.login_with_password(client, "work@example.com")
        authorization = google.authorize(csrf_post(client, "/auth/google/link/"))

        response = google.callback(client, authorization)

        assert error_of(response) == "email_mismatch"
        assert not SocialAccount.objects.exists()

    def test_unverified_provider_email_cannot_be_linked(
        self, client: Client, google: FakeGoogle
    ) -> None:
        self.login_with_password(client)
        authorization = google.authorize(csrf_post(client, "/auth/google/link/"))

        response = google.callback(client, authorization, Account(email_verified=False))

        assert error_of(response) == "email_not_verified"

    def test_linking_promotes_an_existing_connection(
        self, client: Client, google: FakeGoogle
    ) -> None:
        user = self.login_with_password(client)
        connect(user, is_login_method=False)

        authorization = google.authorize(csrf_post(client, "/auth/google/link/"))
        google.callback(client, authorization)

        assert SocialAccount.objects.get().is_login_method


class TestDisconnect:
    def path(self, account: SocialAccount) -> str:
        return f"/auth/google/accounts/{account.pk}/disconnect/"

    def test_last_login_method_is_kept(
        self, client: Client, google: FakeGoogle
    ) -> None:
        sign_in(client, google)
        account = SocialAccount.objects.get()

        response = csrf_post(client, self.path(account))

        assert error_of(response) == "no_alternative_login_method"
        assert SocialAccount.objects.filter(pk=account.pk).exists()

    def test_password_user_can_disconnect(self, client: Client) -> None:
        user = make_user("person@gmail.com", password="secret")
        account = connect(user)
        client.force_login(user, backend="django.contrib.auth.backends.ModelBackend")

        response = csrf_post(client, self.path(account), {"next": "/private/"})

        assert response.status_code == 302
        assert response["Location"] == "/private/"
        assert not SocialAccount.objects.exists()

    def test_disconnect_requires_post_csrf_and_ownership(self, client: Client) -> None:
        owner = make_user("owner@example.com", password="secret")
        account = connect(owner)
        client.force_login(make_user("other@example.com", password="secret"))

        assert client.get(self.path(account)).status_code == 405
        assert client.post(self.path(account)).status_code == 403
        response = csrf_post(client, self.path(account))
        assert error_of(response) == "account_not_connected"
        assert SocialAccount.objects.filter(pk=account.pk).exists()

    def test_disconnect_requires_a_signed_in_user(self, client: Client) -> None:
        account = connect(make_user("owner@example.com", password="secret"))

        assert csrf_post(client, self.path(account)).status_code == 401


LOGIN_START = ["before_authorization", "authorization_started"]
SIGN_UP = [
    *LOGIN_START,
    "before_callback",
    "before_user_create",
    "before_social_account_create",
    "user_created",
    "social_account_created",
    "before_login",
    "after_login",
]
RETURNING_SIGN_IN = [
    *LOGIN_START,
    "before_callback",
    "before_social_account_update",
    "social_account_updated",
    "before_login",
    "after_login",
]
LINK = [
    "before_authorization",
    "authorization_started",
    "before_callback",
    "before_social_account_create",
    "social_account_created",
    "social_account_linked",
]
# Raw provider credentials no receiver should see.
SECRETS = {"google-access-token", "test-client-secret"}


def refuse(**kwargs: Any) -> None:
    raise PermissionDenied("Not allowed.")


def password_user(client: Client, email: str = "person@gmail.com") -> Any:
    user = make_user(email, password="secret")
    client.force_login(user, backend="django.contrib.auth.backends.ModelBackend")
    return user


def link(client: Client, google: FakeGoogle) -> HttpResponseBase:
    authorization = google.authorize(csrf_post(client, "/auth/google/link/"))
    return google.callback(client, authorization)


def stored_states() -> int:
    return ExpiringValue.objects.filter(
        key__startswith="oauth:authorization_request"
    ).count()


class TestSignals:
    def test_sign_up_sends_each_signal_once(
        self, client: Client, google: FakeGoogle
    ) -> None:
        def native_login(sender: object, **kwargs: Any) -> None:
            signals.events.append(("user_logged_in", kwargs))

        user_logged_in.connect(native_login)
        try:
            sign_in(client, google)
        finally:
            user_logged_in.disconnect(native_login)

        # Django sends its own user_logged_in inside login(); Cross Auth does
        # not send it again and after_login follows the saved session.
        expected = list(SIGN_UP)
        expected.insert(expected.index("after_login"), "user_logged_in")
        assert sent() == expected
        User = get_user_model()
        for name, kwargs in signals.events:
            if name == "user_logged_in":
                continue
            assert kwargs["sender"] is User, name
            assert kwargs["provider"] == "google", name
            assert isinstance(kwargs["request"], HttpRequest), name

    def test_before_signals_get_values_not_records(
        self, client: Client, google: FakeGoogle
    ) -> None:
        sign_in(client, google)
        user_id = whoami(client)["user_id"]
        account = SocialAccount.objects.get()

        common = {"signal", "sender", "request", "provider"}
        assert payload("before_authorization").keys() - common == {"flow", "user_id"}
        assert payload("before_authorization")["flow"] == "login"
        assert payload("before_authorization")["user_id"] is None
        assert payload("before_callback").keys() - common == {
            "flow",
            "provider_user_id",
            "email",
            "email_verified",
            "user_id",
        }
        before_callback = payload("before_callback")
        assert before_callback["flow"] == "login"
        assert before_callback["provider_user_id"] == "google-sub-1"
        assert before_callback["email"] == "person@gmail.com"
        assert before_callback["email_verified"] is True
        assert before_callback["user_id"] is None
        before_create = payload("before_user_create")
        assert before_create.keys() - common == {"email", "email_verified"}
        assert before_create["email"] == "person@gmail.com"
        assert before_create["email_verified"] is True
        before_account = payload("before_social_account_create")
        assert before_account.keys() - common == {
            "user_id",
            "provider_user_id",
            "email",
            "email_verified",
            "is_login_method",
        }
        assert before_account["user_id"] == user_id
        assert before_account["provider_user_id"] == "google-sub-1"
        assert before_account["is_login_method"] is True
        before = payload("before_login")
        assert before.keys() - common == {"user_id", "email"}
        assert before["user_id"] == user_id
        assert before["email"] == "person@gmail.com"

        signals.events.clear()
        sign_in(Client(enforce_csrf_checks=True), google)
        before_update = payload("before_social_account_update")
        assert before_update.keys() - common == {
            "social_account_id",
            "user_id",
            "provider_user_id",
            "email",
            "email_verified",
            "is_login_method",
        }
        assert before_update["social_account_id"] == str(account.pk)
        assert before_update["user_id"] == user_id

        # Plain values only: no users, accounts, providers or credentials.
        for name, kwargs in signals.events:
            if not name.startswith("before_"):
                continue
            for key, value in kwargs.items():
                if key in common:
                    continue
                assert value is None or type(value) in {str, bool}, (name, key)
                assert value not in SECRETS, (name, key)

    def test_after_signals_get_the_native_user_and_request(
        self, client: Client, google: FakeGoogle
    ) -> None:
        seen: dict[str, Any] = {}

        def check_session(request: HttpRequest, **kwargs: Any) -> None:
            seen["session_stored"] = Session.objects.filter(
                session_key=request.session.session_key
            ).exists()
            seen["session_user"] = request.session["_auth_user_id"]
            seen["request_user"] = request.user

        signals.handlers["after_login"] = check_session

        sign_in(client, google)

        User = get_user_model()
        common = {"signal", "sender", "request", "provider"}
        created = payload("user_created")
        assert created.keys() - common == {"user"}
        native = created["user"]
        assert type(native) is User
        assert native._state.db == "default"
        assert str(native.pk) == whoami(client)["user_id"]
        if CUSTOM_USER:
            assert isinstance(native.pk, uuid.UUID)
        account = payload("social_account_created")
        assert account.keys() - common == {"social_account"}
        assert type(account["social_account"]) is SocialAccount
        assert account["social_account"]._state.db == "default"
        assert account["social_account"].pk == SocialAccount.objects.get().pk
        assert account["social_account"].user_id == native.pk
        after = payload("after_login")
        assert after.keys() - common == {"user"}
        assert type(after["user"]) is User
        assert after["user"].pk == native.pk
        assert seen == {
            "session_stored": True,
            "session_user": str(native.pk),
            "request_user": after["user"],
        }

    def test_returning_sign_in_refreshes_the_account_once(
        self, client: Client, google: FakeGoogle
    ) -> None:
        sign_in(client, google)
        signals.events.clear()

        sign_in(
            Client(enforce_csrf_checks=True), google, Account(email="new@gmail.com")
        )

        assert sent() == RETURNING_SIGN_IN
        assert payload("before_social_account_update")["email"] == "new@gmail.com"
        updated = payload("social_account_updated")["social_account"]
        assert type(updated) is SocialAccount
        assert updated.provider_email == "new@gmail.com"
        assert updated.pk == SocialAccount.objects.get().pk

    def test_before_login_permission_denied_is_forbidden(
        self, client: Client, google: FakeGoogle
    ) -> None:
        sign_in(Client(enforce_csrf_checks=True), google)
        signals.events.clear()
        sessions = Session.objects.count()
        signals.handlers["before_login"] = refuse

        response = sign_in(client, google)

        assert response.status_code == 403
        assert whoami(client)["authenticated"] is False
        assert sent() == RETURNING_SIGN_IN[:-1]
        assert Session.objects.count() == sessions

    def test_before_user_create_permission_denied_creates_nothing(
        self, client: Client, google: FakeGoogle
    ) -> None:
        signals.handlers["before_user_create"] = refuse

        response = sign_in(client, google)

        assert response.status_code == 403
        assert sent() == [*LOGIN_START, "before_callback", "before_user_create"]
        assert not get_user_model()._default_manager.exists()
        assert not SocialAccount.objects.exists()
        assert whoami(client)["authenticated"] is False

    def test_return_values_are_ignored(
        self, client: Client, google: FakeGoogle
    ) -> None:
        rewrite = {"email": "attacker@example.com", "provider_user_id": "attacker"}
        for name in (
            "before_callback",
            "before_user_create",
            "before_social_account_create",
        ):
            signals.handlers[name] = lambda **kwargs: rewrite
        signals.handlers["before_login"] = lambda **kwargs: False

        sign_in(client, google)

        native = get_user_model()._default_manager.get()
        assert DjangoUser(native, password_login=True).email == "person@gmail.com"
        account = SocialAccount.objects.get()
        assert account.provider_user_id == "google-sub-1"
        assert account.provider_email == "person@gmail.com"
        assert whoami(client)["authenticated"] is True

    def test_user_created_follows_the_committed_sign_up(
        self, client: Client, google: FakeGoogle
    ) -> None:
        seen: list[tuple[str, bool, bool]] = []

        def committed(name: str) -> Callable[..., None]:
            def check(**kwargs: Any) -> None:
                native = kwargs.get("user") or kwargs["social_account"].user
                seen.append(
                    (
                        name,
                        connections["default"].in_atomic_block,
                        SocialAccount.objects.filter(user_id=native.pk).exists(),
                    )
                )

            return check

        signals.handlers["user_created"] = committed("user_created")
        signals.handlers["social_account_created"] = committed("social_account")

        sign_in(client, google)

        assert seen == [("user_created", False, True), ("social_account", False, True)]

    def test_user_created_follows_the_factory_rows(
        self, client: Client, google: FakeGoogle
    ) -> None:
        from .testapp.models import Profile

        profiles: list[bool] = []
        signals.handlers["user_created"] = lambda user, **kwargs: profiles.append(
            Profile.objects.filter(user=user).exists()
        )
        signals.handlers["social_account_created"] = (
            lambda social_account, **kwargs: profiles.append(
                Profile.objects.filter(user_id=social_account.user_id).exists()
            )
        )

        with override_settings(
            CROSS_AUTH={
                **settings.CROSS_AUTH,
                "CREATE_USER": "tests.django.factories.with_profile",
            }
        ):
            sign_in(client, google)

        assert profiles == [True, True]

    def test_failed_sign_up_sends_no_user_created(
        self, client: Client, google: FakeGoogle
    ) -> None:
        with (
            override_settings(
                CROSS_AUTH={
                    **settings.CROSS_AUTH,
                    "CREATE_USER": "tests.django.factories.with_duplicate_profile",
                }
            ),
            pytest.raises(IntegrityError),
        ):
            sign_in(client, google)

        assert sent() == [*LOGIN_START, "before_callback", "before_user_create"]
        assert not get_user_model()._default_manager.exists()
        assert not SocialAccount.objects.exists()

    def test_lost_sign_up_race_sends_no_user_created(
        self, client: Client, google: FakeGoogle
    ) -> None:
        # Another sign-up commits this email after the lookup found none.
        def concurrent_sign_up(**kwargs: Any) -> None:
            make_user("person@gmail.com")

        signals.handlers["before_user_create"] = concurrent_sign_up

        response = sign_in(client, google)

        assert error_of(response) == "account_not_linked"
        assert sent() == [*LOGIN_START, "before_callback", "before_user_create"]
        assert not SocialAccount.objects.exists()

    @pytest.mark.parametrize("error", [RuntimeError("boom"), IntegrityError("app")])
    def test_user_created_errors_propagate_after_commit(
        self, client: Client, google: FakeGoogle, error: Exception
    ) -> None:
        def fail(**kwargs: Any) -> None:
            raise error

        signals.handlers["user_created"] = fail

        with pytest.raises(type(error)):
            sign_in(client, google)

        # The sign-up is committed and not retried; nobody is logged in.
        native = get_user_model()._default_manager.get()
        assert SocialAccount.objects.get().user_id == native.pk
        assert sent() == SIGN_UP[: SIGN_UP.index("user_created") + 1]
        assert whoami(client)["authenticated"] is False

    def test_after_login_errors_propagate_after_the_session_is_saved(
        self, client: Client, google: FakeGoogle
    ) -> None:
        def fail(**kwargs: Any) -> None:
            raise RuntimeError("boom")

        signals.handlers["after_login"] = fail

        with pytest.raises(RuntimeError):
            sign_in(client, google)

        native = get_user_model()._default_manager.get()
        stored = [session.get_decoded() for session in Session.objects.all()]
        assert [data["_auth_user_id"] for data in stored] == [str(native.pk)]
        assert sent().count("after_login") == 1

    def test_password_login_sends_nothing(self, client: Client) -> None:
        make_user("person@gmail.com", password="secret")

        assert client.login(username="person@gmail.com", password="secret")
        csrf_post(client, "/accounts/logout/")

        assert sent() == []

    def test_failed_callback_sends_no_callback_signals(
        self, client: Client, google: FakeGoogle
    ) -> None:
        authorization = start_login(client, google)

        client.get(
            "/auth/google/callback",
            {"state": authorization.state, "error": "access_denied"},
        )

        assert sent() == LOGIN_START

    def test_reloading_settings_and_apps_does_not_duplicate_signals(
        self, client: Client, google: FakeGoogle
    ) -> None:
        apps.get_app_config("testapp").ready()
        apps.get_app_config("cross_auth").ready()

        with override_settings(CROSS_AUTH={**settings.CROSS_AUTH}):
            sign_in(client, google)

        assert sent() == SIGN_UP


class TestAuthorizationSignals:
    def test_login_signals_follow_the_stored_state(
        self, client: Client, google: FakeGoogle
    ) -> None:
        states: list[int] = []
        signals.handlers["before_authorization"] = lambda **kwargs: states.append(
            stored_states()
        )
        signals.handlers["authorization_started"] = lambda **kwargs: states.append(
            stored_states()
        )

        start_login(client, google)

        assert sent() == LOGIN_START
        assert states == [0, 1]
        started = payload("authorization_started")
        assert started.keys() == {"signal", "sender", "request", "provider", "flow"}
        assert started["flow"] == "login"
        assert started["sender"] is get_user_model()

    def test_link_signals_name_the_signed_in_user(
        self, client: Client, google: FakeGoogle
    ) -> None:
        user = password_user(client)
        seen: list[Any] = []
        signals.handlers["authorization_started"] = (
            lambda request, **kwargs: seen.append(request.user.pk)
        )

        google.authorize(csrf_post(client, "/auth/google/link/"))

        assert sent() == ["before_authorization", "authorization_started"]
        assert payload("before_authorization")["flow"] == "link"
        assert payload("before_authorization")["user_id"] == str(user.pk)
        assert payload("authorization_started")["flow"] == "link"
        assert seen == [user.pk]

    @pytest.mark.parametrize("path", ["/auth/google/login/", "/auth/google/link/"])
    def test_refused_authorization_stores_nothing(
        self, client: Client, path: str
    ) -> None:
        password_user(client)
        signals.handlers["before_authorization"] = refuse

        response = csrf_post(client, path)

        assert response.status_code == 403
        assert sent() == ["before_authorization"]
        assert stored_states() == 0
        assert not [name for name in response.cookies if name.startswith("cross")]

    def test_signed_out_link_sends_nothing(self, client: Client) -> None:
        assert csrf_post(client, "/auth/google/link/").status_code == 401
        assert sent() == []

    def test_failed_state_write_sends_no_authorization_started(
        self, client: Client, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def fail(*args: Any, **kwargs: Any) -> None:
            raise RuntimeError("storage down")

        monkeypatch.setattr(DjangoSecondaryStorage, "set", fail)

        with pytest.raises(RuntimeError):
            csrf_post(client, "/auth/google/login/")

        assert sent() == ["before_authorization"]


class TestCallbackSignals:
    def test_before_callback_follows_verification(
        self, client: Client, google: FakeGoogle
    ) -> None:
        seen: list[tuple[int, int, int]] = []
        signals.handlers["before_callback"] = lambda **kwargs: seen.append(
            (
                stored_states(),
                get_user_model()._default_manager.count(),
                SocialAccount.objects.count(),
            )
        )

        sign_in(client, google)

        # The state is consumed and nothing is looked up or written yet.
        assert seen == [(0, 0, 0)]

    def test_refused_sign_in_callback_writes_nothing(
        self, client: Client, google: FakeGoogle
    ) -> None:
        sign_in(Client(enforce_csrf_checks=True), google)
        account = SocialAccount.objects.get()
        sessions = Session.objects.count()
        signals.events.clear()
        signals.handlers["before_callback"] = refuse

        response = sign_in(client, google, Account(email="new@gmail.com"))
        first = sign_in(
            Client(enforce_csrf_checks=True), google, Account(sub="google-sub-2")
        )

        assert response.status_code == first.status_code == 403
        assert sent() == [*LOGIN_START, "before_callback"] * 2
        assert SocialAccount.objects.get().provider_email == account.provider_email
        assert get_user_model()._default_manager.count() == 1
        assert Session.objects.count() == sessions
        assert whoami(client)["authenticated"] is False

    def test_unverified_callbacks_send_no_before_callback(
        self, google: FakeGoogle
    ) -> None:
        # Wrong nonce, another browser, a forged code and a replay.
        client = Client(enforce_csrf_checks=True)
        authorization = start_login(client, google)
        authorization.params["nonce"] = "attacker-nonce"
        assert error_of(google.callback(client, authorization)) == "invalid_token"

        authorization = start_login(client, google)
        attacker = Client(enforce_csrf_checks=True)
        assert error_of(google.callback(attacker, authorization)) == "invalid_request"
        forged = {"state": authorization.state, "code": "forged"}
        assert client.get("/auth/google/callback", forged).status_code == 400
        assert "before_callback" not in sent()

        authorization = start_login(client, google)
        code = google.approve(authorization, Account())
        params = {"state": authorization.state, "code": code}
        assert client.get("/auth/google/callback", params).status_code == 302
        signals.events.clear()
        assert client.get("/auth/google/callback", params).status_code >= 300

        assert sent() == []

    def test_link_callback_names_the_linking_user(
        self, client: Client, google: FakeGoogle
    ) -> None:
        user = password_user(client)

        link(client, google)

        assert sent() == LINK
        before = payload("before_callback")
        assert before["flow"] == "link"
        assert before["user_id"] == str(user.pk)
        assert before["provider_user_id"] == "google-sub-1"
        assert payload("before_social_account_create")["user_id"] == str(user.pk)
        account = SocialAccount.objects.get()
        for name in ("social_account_created", "social_account_linked"):
            assert payload(name)["social_account"].pk == account.pk
            assert payload(name)["social_account"].user_id == user.pk
        # Linking is not a login.
        assert whoami(client)["backend"] == "django.contrib.auth.backends.ModelBackend"

    @pytest.mark.parametrize(
        "name", ["before_callback", "before_social_account_create"]
    )
    def test_refused_link_writes_nothing(
        self, client: Client, google: FakeGoogle, name: str
    ) -> None:
        user = password_user(client)
        signals.handlers[name] = refuse

        response = link(client, google)

        assert response.status_code == 403
        assert sent()[-1] == name
        assert not SocialAccount.objects.exists()
        assert whoami(client)["user_id"] == str(user.pk)

    def test_link_promotion_is_an_update(
        self, client: Client, google: FakeGoogle
    ) -> None:
        user = password_user(client)
        connect(user, is_login_method=False)

        link(client, google)

        assert sent() == [
            *LOGIN_START,
            "before_callback",
            "before_social_account_update",
            "social_account_updated",
            "social_account_linked",
        ]
        assert payload("before_social_account_update")["is_login_method"] is False
        linked = payload("social_account_linked")["social_account"]
        assert linked.is_login_method is True
        assert payload("social_account_updated")["social_account"] is linked

    def test_failed_link_sends_no_linked(
        self, client: Client, google: FakeGoogle
    ) -> None:
        owner = make_user("owner@example.com")
        connect(owner)
        password_user(client)

        response = link(client, google)

        assert error_of(response) == "account_already_linked"
        assert sent() == [
            *LOGIN_START,
            "before_callback",
            "before_social_account_create",
        ]

    @pytest.mark.parametrize("error", [RuntimeError("boom"), IntegrityError("app")])
    def test_social_account_created_errors_propagate_after_commit(
        self, client: Client, google: FakeGoogle, error: Exception
    ) -> None:
        def fail(**kwargs: Any) -> None:
            raise error

        user = password_user(client)
        signals.handlers["social_account_created"] = fail

        with pytest.raises(type(error)):
            link(client, google)

        assert SocialAccount.objects.get().user_id == user.pk
        assert sent() == LINK[:-1]

    def test_refused_refresh_does_not_log_in(
        self, client: Client, google: FakeGoogle
    ) -> None:
        sign_in(Client(enforce_csrf_checks=True), google)
        signals.events.clear()
        signals.handlers["before_social_account_update"] = refuse

        response = sign_in(client, google, Account(email="new@gmail.com"))

        assert response.status_code == 403
        assert sent() == RETURNING_SIGN_IN[:4]
        assert SocialAccount.objects.get().provider_email == "person@gmail.com"
        assert whoami(client)["authenticated"] is False

    def test_refused_sign_up_identity_rolls_back_the_user(
        self, client: Client, google: FakeGoogle
    ) -> None:
        signals.handlers["before_social_account_create"] = refuse

        response = sign_in(client, google)

        assert response.status_code == 403
        assert sent() == SIGN_UP[: SIGN_UP.index("before_social_account_create") + 1]
        assert not get_user_model()._default_manager.exists()
        assert not SocialAccount.objects.exists()


class TestDisconnectSignals:
    def path(self, account: SocialAccount) -> str:
        return f"/auth/google/accounts/{account.pk}/disconnect/"

    def test_disconnect_sends_after_the_committed_removal(self, client: Client) -> None:
        user = password_user(client)
        account = connect(user)
        seen: list[tuple[bool, bool]] = []
        signals.handlers["social_account_disconnected"] = lambda **kwargs: seen.append(
            (
                connections["default"].in_atomic_block,
                SocialAccount.objects.filter(pk=account.pk).exists(),
            )
        )

        response = csrf_post(client, self.path(account))

        assert response.status_code == 302
        assert sent() == [
            "before_social_account_disconnect",
            "social_account_disconnected",
        ]
        before = payload("before_social_account_disconnect")
        assert before.keys() - {"signal", "sender", "request", "provider"} == {
            "social_account_id",
            "user_id",
            "provider_user_id",
        }
        assert before["social_account_id"] == str(account.pk)
        assert before["user_id"] == str(user.pk)
        assert before["provider_user_id"] == "google-sub-1"
        removed = payload("social_account_disconnected")["social_account"]
        assert type(removed) is SocialAccount
        assert (removed.pk, removed.user_id) == (account.pk, user.pk)
        assert seen == [(False, False)]

    def test_refused_disconnect_keeps_the_account(self, client: Client) -> None:
        account = connect(password_user(client))
        signals.handlers["before_social_account_disconnect"] = refuse

        response = csrf_post(client, self.path(account))

        assert response.status_code == 403
        assert sent() == ["before_social_account_disconnect"]
        assert SocialAccount.objects.filter(pk=account.pk).exists()

    def test_kept_last_login_method_sends_no_disconnected(
        self, client: Client, google: FakeGoogle
    ) -> None:
        sign_in(client, google)
        account = SocialAccount.objects.get()
        signals.events.clear()

        response = csrf_post(client, self.path(account))

        assert error_of(response) == "no_alternative_login_method"
        assert sent() == ["before_social_account_disconnect"]

    def test_someone_elses_account_sends_nothing(self, client: Client) -> None:
        account = connect(make_user("owner@example.com", password="secret"))
        password_user(client, "other@example.com")

        assert error_of(csrf_post(client, self.path(account))) == (
            "account_not_connected"
        )
        assert sent() == []

    @pytest.mark.parametrize("error", [RuntimeError("boom"), IntegrityError("app")])
    def test_disconnected_errors_propagate_after_commit(
        self, client: Client, error: Exception
    ) -> None:
        def fail(**kwargs: Any) -> None:
            raise error

        account = connect(password_user(client))
        signals.handlers["social_account_disconnected"] = fail

        with pytest.raises(type(error)):
            csrf_post(client, self.path(account))

        assert not SocialAccount.objects.exists()
        assert sent().count("social_account_disconnected") == 1


class TestSignalCommits:
    """Account signals follow Django's commit, as ``on_commit`` callbacks."""

    @pytest.fixture
    def context(self) -> Context:
        provider = get_settings().providers["google"]
        request = RequestFactory().get("/auth/google/callback")
        return views._context(request, views._Signals(request, provider))

    def create(self, context: Context, user: Any, sub: str) -> None:
        _create_social_account(
            context=context,
            user_id=user.pk,
            provider="google",
            provider_user_id=sub,
            access_token=None,
            refresh_token=None,
            access_token_expires_at=None,
            refresh_token_expires_at=None,
            scope=None,
            user_info={"id": sub},
            provider_email=None,
            provider_email_verified=None,
            is_login_method=False,
        )

    def test_sent_when_the_outer_transaction_commits(self, context: Context) -> None:
        user = make_user("person@gmail.com")

        with transaction.atomic():
            self.create(context, user, "google-sub-1")
            assert sent() == ["before_social_account_create"]

        assert sent() == ["before_social_account_create", "social_account_created"]

    def test_not_sent_when_the_transaction_rolls_back(self, context: Context) -> None:
        user = make_user("person@gmail.com")

        with pytest.raises(RuntimeError), transaction.atomic():
            self.create(context, user, "google-sub-1")
            raise RuntimeError("rollback")

        assert sent() == ["before_social_account_create"]
        assert not SocialAccount.objects.exists()

    def test_not_sent_for_a_rolled_back_savepoint(self, context: Context) -> None:
        user = make_user("person@gmail.com")

        with transaction.atomic():
            self.create(context, user, "google-sub-1")
            with pytest.raises(RuntimeError), transaction.atomic():
                self.create(context, user, "google-sub-2")
                raise RuntimeError("rollback")

        created = [
            kwargs["social_account"].provider_user_id
            for name, kwargs in signals.events
            if name == "social_account_created"
        ]
        assert created == ["google-sub-1"]
        assert SocialAccount.objects.get().provider_user_id == "google-sub-1"


class TestTransactions:
    def test_views_opt_out_of_atomic_requests(
        self, client: Client, google: FakeGoogle, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Django reads ATOMIC_REQUESTS from the connection on each request.
        monkeypatch.setitem(
            connections["default"].settings_dict, "ATOMIC_REQUESTS", True
        )

        sign_in(client, google)

        assert whoami(client)["authenticated"] is True

    def test_enclosing_transaction_is_rejected(
        self, client: Client, google: FakeGoogle
    ) -> None:
        from django.core.exceptions import ImproperlyConfigured

        with pytest.raises(ImproperlyConfigured, match="transaction.atomic"):
            with transaction.atomic():
                csrf_post(client, "/auth/google/login/")


class TestServers:
    def test_asgi_sign_in(self, google: FakeGoogle) -> None:
        client = AsyncClient()

        async def flow() -> tuple[int, dict[str, Any]]:
            await client.get("/")
            response = await client.post(
                "/auth/google/login/",
                {"csrfmiddlewaretoken": client.cookies["csrftoken"].value},
            )
            authorization = google.authorize(response)
            code = google.approve(authorization, Account())
            callback = await client.get(
                "/auth/google/callback", {"state": authorization.state, "code": code}
            )
            return callback.status_code, (await client.get("/")).json()

        status, me = async_to_sync(flow)()

        assert status == 302
        assert me["authenticated"] is True
        assert me["backend"] == BACKEND


def test_redirect_uri_matches_the_callback_route(
    client: Client, google: FakeGoogle
) -> None:
    from django.urls import reverse

    authorization = start_login(client, google)

    path = urlparse(authorization.params["redirect_uri"]).path
    assert path == reverse("cross_auth:callback", kwargs={"provider": "google"})
    assert parse_qs(urlparse(authorization.url).query)["redirect_uri"] == [CALLBACK]
    if CUSTOM_USER:
        assert get_user_model()._meta.pk.get_internal_type() == "UUIDField"
