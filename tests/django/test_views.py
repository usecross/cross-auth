"""Browser flows through Django's test client with CSRF checks enforced.

Views run as real requests through Django's middleware with committed
transactions (``transaction=True``); only Google's network is faked.
"""

from __future__ import annotations

import re
import threading
from collections.abc import Iterator
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
import respx
from asgiref.sync import async_to_sync
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission, PermissionsMixin
from django.contrib.sessions.models import Session
from django.db import connections, transaction
from django.http import HttpResponse, HttpResponseBase
from django.test import AsyncClient, Client, override_settings

from cross_auth.django.models import SocialAccount
from cross_auth.django.storage import DjangoAccountsStorage, DjangoUser
from cross_auth.exceptions import CrossAuthException
from cross_auth.hooks import AfterLoginEvent, BeforeLoginEvent

from . import hooks
from .conftest import CUSTOM_USER, connect, make_user
from .fake_google import CALLBACK, Account, Authorization, FakeGoogle

pytestmark = pytest.mark.django_db(transaction=True)

BACKEND = "cross_auth.django.backends.CrossAuthBackend"


@pytest.fixture
def google() -> Iterator[FakeGoogle]:
    with respx.mock(assert_all_called=False) as router:
        fake = FakeGoogle(router)
        fake.install()
        yield fake


@pytest.fixture(autouse=True)
def reset_hooks() -> Iterator[None]:
    hooks.events.clear()
    hooks.handlers.clear()
    yield
    hooks.events.clear()
    hooks.handlers.clear()


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
        assert [name for name, _ in hooks.events].count("before login") == 1

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
        names = [name for name, _ in hooks.events]
        assert names.count("after user.create") == 1
        assert names.count("after login") == 1

        # Signing in again from the losing browser reaches the same user.
        loser_client = clients[responses.index(loser)]
        assert sign_in(loser_client, google)["Location"] == "/"
        assert whoami(loser_client)["user_id"] == str(native.pk)
        assert get_user_model()._default_manager.count() == 1
        assert [name for name, _ in hooks.events].count("after user.create") == 1

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


class TestLoginHooks:
    def test_login_hooks_wrap_the_native_login(
        self, client: Client, google: FakeGoogle
    ) -> None:
        stored: list[bool] = []

        def after(event: AfterLoginEvent) -> None:
            # The rotated session is already in the database.
            stored.append(Session.objects.exists())

        hooks.handlers["after login"] = after

        sign_in(client, google)

        names = [name for name, _ in hooks.events]
        assert names == ["after user.create", "before login", "after login"]
        before = hooks.events[1][1]
        assert isinstance(before, BeforeLoginEvent)
        assert before.credential == "django_session"
        assert before.user_id == whoami(client)["user_id"]
        assert before.max_age is None
        assert hooks.events[2][1].session_record is None
        assert stored == [True]

    def test_before_login_can_refuse(self, client: Client, google: FakeGoogle) -> None:
        def refuse(event: BeforeLoginEvent) -> None:
            raise CrossAuthException("access_denied", "Not today", status_code=403)

        hooks.handlers["before login"] = refuse

        response = sign_in(client, google)

        assert error_of(response) == "access_denied"
        assert whoami(client)["authenticated"] is False


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
