"""The OAuth server's views and bearer tokens, through Django's test client.

A client's sign-in starts at the authorize view in the user's browser, goes
to Google (faked) and back to the callback, and ends at the client's redirect
URI with a code. The client's own code then posts that code to the token view
from elsewhere: those requests carry no cookie and no CSRF token.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

import pytest
import time_machine
from django.conf import settings
from django.contrib.auth import get_user_model, user_logged_in
from django.core.exceptions import ImproperlyConfigured, PermissionDenied
from django.db import connections, transaction
from django.http import HttpResponse, HttpResponseBase
from django.test import Client, RequestFactory, override_settings

from cross_auth._authorization_code import AUTH_CODE_KEY
from cross_auth.django.models import ExpiringValue, Session, SocialAccount
from cross_auth.django.tokens import authenticate_bearer

from . import clients
from .clients import NATIVE_REDIRECT, SPA_REDIRECT
from .fake_google import Account, FakeGoogle
from .support import connect, make_user, sign_in, whoami
from .testapp import signals

pytestmark = pytest.mark.django_db(transaction=True)

USER_AGENT = "ExampleApp/3.2 (iPhone; iOS 19.1)"
IP = "203.0.113.7"
T0 = datetime(2026, 11, 19, 12, 0, tzinfo=timezone.utc)
DAY = 24 * 60 * 60


def oauth_server(**options: object) -> override_settings:
    return override_settings(
        CROSS_AUTH={
            **settings.CROSS_AUTH,
            "OAUTH_SERVER": {
                "get_client": "tests.django.clients.get_client",
                **options,
            },
        }
    )


@pytest.fixture(autouse=True)
def enabled() -> Iterator[None]:
    clients.reset()
    signals.events.clear()
    signals.handlers.clear()
    with oauth_server():
        yield
    signals.events.clear()
    signals.handlers.clear()
    clients.reset()


def sent() -> list[str]:
    return [name for name, _ in signals.events]


def payload(name: str) -> dict[str, Any]:
    [kwargs] = [kwargs for sent_name, kwargs in signals.events if sent_name == name]
    return kwargs


def refuse(**kwargs: Any) -> None:
    raise PermissionDenied("Not allowed.")


@dataclass
class Pkce:
    verifier: str = field(default_factory=lambda: secrets.token_urlsafe(48))

    @property
    def challenge(self) -> str:
        digest = hashlib.sha256(self.verifier.encode()).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def browser() -> Client:
    return Client(enforce_csrf_checks=True)


def app() -> Client:
    """The client's own code: no cookies of the browser's, no CSRF token."""
    return Client(
        enforce_csrf_checks=True,
        headers={"User-Agent": USER_AGENT},
        REMOTE_ADDR=IP,
    )


def authorize(
    client: Client, pkce: Pkce | None = None, /, **overrides: str | None
) -> Any:
    params: dict[str, str | None] = {
        "client_id": "spa",
        "redirect_uri": SPA_REDIRECT,
        "response_type": "code",
        "state": "client-state",
        "code_challenge": (pkce or Pkce()).challenge,
        "code_challenge_method": "S256",
        **overrides,
    }
    return client.get(
        "/auth/google/authorize",
        {key: value for key, value in params.items() if value is not None},
    )


def redirected(response: HttpResponseBase, to: str = SPA_REDIRECT) -> dict[str, str]:
    """The query the sign-in sent the browser back to the client with."""
    assert response.status_code == 302, response.status_code
    location = response["Location"]
    assert location.split("?")[0] == to, location
    return {
        key: values[0] for key, values in parse_qs(urlparse(location).query).items()
    }


def code_for(
    client: Client,
    google: FakeGoogle,
    pkce: Pkce,
    account: Account | None = None,
    **overrides: str | None,
) -> str:
    """Sign in through the browser and return the code the client receives."""
    authorization = google.authorize(authorize(client, pkce, **overrides))
    response = google.callback(client, authorization, account)
    return redirected(response, overrides.get("redirect_uri") or SPA_REDIRECT)["code"]


def post_token(form: dict[str, str]) -> Any:
    """Post a form to the token view as an OAuth client does: URL-encoded."""
    return app().post(
        "/auth/token",
        urlencode(form),
        content_type="application/x-www-form-urlencoded",
    )


def exchange(code: str, pkce: Pkce, /, **overrides: str) -> Any:
    return post_token(
        {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": "spa",
            "redirect_uri": SPA_REDIRECT,
            "code_verifier": pkce.verifier,
            **overrides,
        }
    )


def token_for(google: FakeGoogle, account: Account | None = None) -> str:
    """Sign in as a client would and return its bearer token."""
    pkce = Pkce()
    response = exchange(code_for(browser(), google, pkce, account), pkce)
    assert response.status_code == 200, response.content
    return response.json()["access_token"]


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def me(token: str, client: Client | None = None) -> Any:
    return (client or app()).get("/api/me", headers=bearer(token))


def logout(token: str | None, body: object = None, **extra: Any) -> Any:
    headers = bearer(token) if token is not None else {}
    if body is None:
        # An empty body, as a client that sends none posts it.
        data = ""
    else:
        data = body if isinstance(body, str) else json.dumps(body)
    return app().post(
        "/auth/logout",
        data=data,
        content_type="application/json",
        headers=headers,
        **extra,
    )


def authorization_codes() -> int:
    """How many codes are waiting for a client to exchange them."""
    prefix = AUTH_CODE_KEY.format(code="")
    return ExpiringValue.objects.filter(key__startswith=prefix).count()


def row_of(token: str) -> Session:
    return Session.objects.get(token_hash=hashlib.sha256(token.encode()).hexdigest())


def page_of(response: HttpResponseBase) -> str:
    """The error page a browser is shown."""
    assert isinstance(response, HttpResponse)
    return response.content.decode()


def error_of(response: Any) -> dict[str, str]:
    """The JSON error a client's own code gets."""
    assert response["Content-Type"] == "application/json", response["Content-Type"]
    return response.json()


class TestWithoutTheOAuthServer:
    @pytest.fixture(autouse=True)
    def disabled(self) -> Iterator[None]:
        with override_settings(
            CROSS_AUTH={
                key: value
                for key, value in settings.CROSS_AUTH.items()
                if key != "OAUTH_SERVER"
            }
        ):
            yield

    def test_its_views_are_not_found(self) -> None:
        assert authorize(browser()).status_code == 404
        assert post_token({"grant_type": "x"}).status_code == 404
        assert app().post("/auth/logout").status_code == 404
        assert ExpiringValue.objects.count() == 0

    def test_authenticate_bearer_says_what_is_missing(self) -> None:
        request = RequestFactory().get("/api/me", headers=bearer("anything"))

        with pytest.raises(ImproperlyConfigured, match="OAUTH_SERVER"):
            authenticate_bearer(request)

    def test_browser_sign_in_is_unchanged(self, google: FakeGoogle) -> None:
        client = browser()

        assert sign_in(client, google).status_code == 302
        assert whoami(client)["authenticated"] is True

    def test_a_sign_in_started_before_it_was_disabled_is_refused(
        self, google: FakeGoogle
    ) -> None:
        client = browser()
        with oauth_server():
            authorization = google.authorize(authorize(client))

        response = google.callback(client, authorization)

        # Not sent to the client's redirect URI, and Google's code is unused.
        assert response.status_code == 400
        assert "OAuth server is disabled" in page_of(response)
        assert google.token_requests == []
        assert get_user_model()._default_manager.count() == 0


class TestAuthorize:
    def test_redirects_to_google_with_pkce_and_a_browser_binding(
        self, google: FakeGoogle
    ) -> None:
        pkce = Pkce()

        response = authorize(browser(), pkce)

        authorization = google.authorize(response)
        assert authorization.params["client_id"] == "test-client-id"
        assert authorization.params["redirect_uri"] == (
            "http://testserver/auth/google/callback"
        )
        # Cross Auth's own state and challenge go to Google, not the client's.
        assert authorization.state != "client-state"
        assert authorization.params["code_challenge"] != pkce.challenge
        assert authorization.params["code_challenge_method"] == "S256"
        assert authorization.params["nonce"]
        binding = [name for name in response.cookies if name.startswith("cross_auth")]
        assert binding == [f"cross_auth_oauth_{authorization.state}"]
        assert response.cookies[binding[0]]["httponly"]
        assert "no-cache" in response["Cache-Control"]

    def test_is_a_get(self) -> None:
        assert Client().post("/auth/google/authorize").status_code == 405

    def test_unknown_provider_is_not_found(self) -> None:
        response = browser().get("/auth/github/authorize", {"client_id": "spa"})

        assert response.status_code == 404

    def test_login_hint_reaches_google(self, google: FakeGoogle) -> None:
        response = authorize(browser(), login_hint="person@gmail.com")

        assert google.authorize(response).params["login_hint"] == "person@gmail.com"

    @pytest.mark.parametrize(
        ("overrides", "error"),
        [
            ({"client_id": None}, "invalid_request"),
            ({"client_id": "unknown"}, "invalid_client"),
            ({"redirect_uri": None}, "invalid_request"),
            (
                {"redirect_uri": "https://evil.example.com/callback"},
                "invalid_redirect_uri",
            ),
            ({"redirect_uri": SPA_REDIRECT + "/"}, "invalid_redirect_uri"),
            # Registered, but for another client.
            ({"redirect_uri": NATIVE_REDIRECT}, "invalid_redirect_uri"),
        ],
    )
    def test_an_unregistered_client_or_redirect_gets_an_error_page(
        self, overrides: dict[str, str | None], error: str
    ) -> None:
        response = authorize(browser(), **overrides)

        # Shown here: nothing is sent to an address that is not registered.
        assert response.status_code == 400
        assert "Location" not in response
        assert f"<code>{error}</code>" in page_of(response)
        assert ExpiringValue.objects.count() == 0
        assert sent() == []

    @pytest.mark.parametrize(
        ("overrides", "description"),
        [
            ({"response_type": None}, "No response type provided"),
            ({"response_type": "token"}, "Unsupported response type"),
            ({"code_challenge": None}, "No code challenge provided"),
            ({"code_challenge_method": "plain"}, "Unsupported code challenge method"),
            ({"code_challenge_method": None}, "Unsupported code challenge method"),
        ],
    )
    def test_a_registered_client_gets_other_errors_at_its_redirect_uri(
        self, overrides: dict[str, str | None], description: str
    ) -> None:
        response = authorize(browser(), **overrides)

        assert redirected(response) == {
            "error": "invalid_request",
            "error_description": description,
            "state": "client-state",
        }
        assert ExpiringValue.objects.count() == 0
        assert sent() == []

    def test_sends_the_authorization_signals(self, google: FakeGoogle) -> None:
        google.authorize(authorize(browser()))

        assert sent() == ["before_authorization", "authorization_started"]
        before = payload("before_authorization")
        assert before["sender"] is get_user_model()
        assert before["provider"] == "google"
        assert (before["flow"], before["user_id"]) == ("authorize", None)
        assert before["request"].path == "/auth/google/authorize"
        assert payload("authorization_started")["flow"] == "authorize"

    def test_before_authorization_can_refuse(self) -> None:
        signals.handlers["before_authorization"] = refuse

        response = authorize(browser())

        # Sent to the client, which gets its state back: Django's 403 page
        # would strand the user in the client's sign-in browser.
        assert redirected(response) == {
            "error": "access_denied",
            "error_description": "Not allowed.",
            "state": "client-state",
        }
        assert sent() == ["before_authorization"]
        assert ExpiringValue.objects.count() == 0

    def test_native_client_with_a_private_scheme(self, google: FakeGoogle) -> None:
        pkce = Pkce()
        client = browser()

        code = code_for(
            client, google, pkce, client_id="native", redirect_uri=NATIVE_REDIRECT
        )
        response = exchange(
            code, pkce, client_id="native", redirect_uri=NATIVE_REDIRECT
        )

        assert response.status_code == 200
        assert row_of(response.json()["access_token"]).client_id == "native"


class TestCallback:
    def test_sends_the_browser_to_the_client_with_a_code(
        self, google: FakeGoogle
    ) -> None:
        client = browser()
        authorization = google.authorize(authorize(client))

        response = google.callback(client, authorization)

        params = redirected(response)
        assert set(params) == {"code", "state"}
        assert params["state"] == "client-state"
        assert "no-cache" in response["Cache-Control"]

    def test_state_is_optional(self, google: FakeGoogle) -> None:
        client = browser()
        authorization = google.authorize(authorize(client, state=None))

        assert set(redirected(google.callback(client, authorization))) == {"code"}

    def test_creates_the_user_but_no_browser_session(self, google: FakeGoogle) -> None:
        client = browser()
        logins: list[object] = []

        def native_login(sender: object, **kwargs: Any) -> None:
            logins.append(kwargs)

        user_logged_in.connect(native_login)
        try:
            code_for(client, google, Pkce())
        finally:
            user_logged_in.disconnect(native_login)

        user = get_user_model()._default_manager.get()
        assert user.get_username() or user.pk
        assert SocialAccount.objects.get().user_id == user.pk
        # The sign-in is for the client: this browser stays signed out, and no
        # token exists until the client exchanges its code.
        assert whoami(client)["authenticated"] is False
        assert logins == []
        assert Session.objects.filter(token_hash__isnull=False).count() == 0

    def test_an_existing_browser_session_stays_as_it_is(
        self, google: FakeGoogle
    ) -> None:
        client = browser()
        sign_in(client, google, Account(sub="first", email="first@gmail.com"))
        first = whoami(client)["user_id"]

        code_for(
            client, google, Pkce(), Account(sub="second", email="second@gmail.com")
        )

        assert whoami(client)["user_id"] == first

    def test_needs_the_browser_that_started_it(self, google: FakeGoogle) -> None:
        authorization = google.authorize(authorize(browser()))

        response = google.callback(browser(), authorization)

        assert response.status_code != 302 or "code=" not in response["Location"]
        assert get_user_model()._default_manager.count() == 0

    def test_inactive_user_is_refused_before_a_code_is_issued(
        self, google: FakeGoogle
    ) -> None:
        connect(make_user("person@example.com", is_active=False))
        client = browser()
        authorization = google.authorize(authorize(client))

        response = google.callback(client, authorization)

        assert redirected(response) == {
            "error": "access_denied",
            "error_description": "This account is inactive.",
            "state": "client-state",
        }
        assert authorization_codes() == 0

    def test_google_refusing_reaches_the_client(self, google: FakeGoogle) -> None:
        client = browser()
        authorization = google.authorize(authorize(client))

        response = client.get(
            "/auth/google/callback",
            {"state": authorization.state, "error": "access_denied"},
        )

        params = redirected(response)
        assert (params["error"], params["state"]) == ("access_denied", "client-state")

    def test_a_client_removed_meanwhile_gets_nothing(self, google: FakeGoogle) -> None:
        client = browser()
        authorization = google.authorize(authorize(client))
        del clients.clients["spa"]

        response = google.callback(client, authorization)

        assert response.status_code == 400
        assert "<code>invalid_redirect_uri</code>" in page_of(response)
        assert google.token_requests == []

    def test_before_callback_names_the_flow(self, google: FakeGoogle) -> None:
        code_for(browser(), google, Pkce())

        before = payload("before_callback")
        assert (before["flow"], before["user_id"]) == ("authorize", None)
        assert before["provider"] == "google"
        assert before["email"] == "person@gmail.com"

    def test_before_callback_can_refuse(self, google: FakeGoogle) -> None:
        signals.handlers["before_callback"] = refuse
        client = browser()
        authorization = google.authorize(authorize(client))

        response = google.callback(client, authorization)

        assert redirected(response) == {
            "error": "access_denied",
            "error_description": "Not allowed.",
            "state": "client-state",
        }
        assert get_user_model()._default_manager.count() == 0
        assert authorization_codes() == 0

    @pytest.mark.parametrize(
        "signal", ["before_user_create", "before_social_account_create"]
    )
    def test_a_refused_sign_up_reaches_the_client(
        self, google: FakeGoogle, signal: str
    ) -> None:
        signals.handlers[signal] = refuse
        client = browser()
        authorization = google.authorize(authorize(client, state=None))

        response = google.callback(client, authorization)

        assert redirected(response) == {
            "error": "access_denied",
            "error_description": "Not allowed.",
        }
        assert get_user_model()._default_manager.count() == 0
        assert authorization_codes() == 0

    def test_a_refused_returning_user_reaches_the_client(
        self, google: FakeGoogle
    ) -> None:
        code_for(browser(), google, Pkce())
        signals.handlers["before_social_account_update"] = refuse
        client = browser()
        authorization = google.authorize(authorize(client))

        response = google.callback(client, authorization)

        assert redirected(response)["error"] == "access_denied"
        assert authorization_codes() == 1

    def test_a_refusal_from_the_user_factory_reaches_the_client(
        self, google: FakeGoogle
    ) -> None:
        # How an application keeps an allow list for new users.
        with override_settings(
            CROSS_AUTH={
                **settings.CROSS_AUTH,
                "CREATE_USER": "tests.django.factories.refuse_everyone",
            }
        ):
            client = browser()
            authorization = google.authorize(authorize(client))

            response = google.callback(client, authorization)

        assert redirected(response) == {
            "error": "access_denied",
            "error_description": "This account has no access.",
            "state": "client-state",
        }
        assert get_user_model()._default_manager.count() == 0

    def test_a_browser_sign_in_keeps_django_403_for_the_same_refusals(
        self, google: FakeGoogle
    ) -> None:
        signals.handlers["before_callback"] = refuse

        response = sign_in(browser(), google)

        assert response.status_code == 403
        assert "Location" not in response


class TestToken:
    def test_exchanges_the_code_for_a_bearer_token(self, google: FakeGoogle) -> None:
        pkce = Pkce()
        with time_machine.travel(T0, tick=False):
            code = code_for(browser(), google, pkce)
            response = exchange(code, pkce)

        assert response.status_code == 200
        assert response["Content-Type"] == "application/json"
        assert "no-store" in response["Cache-Control"]
        body = response.json()
        assert body["token_type"] == "Bearer"
        assert body["expires_in"] == DAY
        assert response.cookies == {}

        user = get_user_model()._default_manager.get()
        session = row_of(body["access_token"])
        assert session.user_id == user.pk
        assert session.client_id == "spa"
        assert session.login_method == "google"
        assert (session.user_agent, session.ip) == (USER_AGENT, IP)
        assert session.created_at == session.updated_at == session.last_activity == T0
        assert session.expire_date == T0 + timedelta(days=1)
        assert session.revoked_at is None
        # Only the token's hash is stored, and it is no session cookie.
        assert body["access_token"] not in (session.session_key, session.token_hash)
        assert session.get_decoded() == {}

    def test_needs_no_cookie_and_no_csrf_token(self, google: FakeGoogle) -> None:
        pkce = Pkce()
        code = code_for(browser(), google, pkce)

        assert exchange(code, pkce).status_code == 200
        assert app().get("/auth/token").status_code == 405

    def test_token_max_age_sets_the_lifetime(self, google: FakeGoogle) -> None:
        with oauth_server(token_max_age=30 * DAY):
            pkce = Pkce()
            with time_machine.travel(T0, tick=False):
                code = code_for(browser(), google, pkce)
                body = exchange(code, pkce).json()

        assert body["expires_in"] == 30 * DAY
        assert row_of(body["access_token"]).expire_date == T0 + timedelta(days=30)

    def test_stores_no_ip_when_sessions_store_none(self, google: FakeGoogle) -> None:
        with override_settings(
            CROSS_AUTH={**settings.CROSS_AUTH, "SESSION_STORE_IP": False}
        ):
            session = row_of(token_for(google))

        assert (session.user_agent, session.ip) == (USER_AGENT, None)

    def test_turning_ip_storage_off_clears_a_tokens_ip_on_its_next_use(
        self, google: FakeGoogle
    ) -> None:
        with time_machine.travel(T0, tick=False):
            token = token_for(google)
            assert me(token).status_code == 200
        assert row_of(token).ip == IP

        with override_settings(
            CROSS_AUTH={**settings.CROSS_AUTH, "SESSION_STORE_IP": False}
        ):
            # Within the activity interval: it does not wait for it.
            with time_machine.travel(T0 + timedelta(minutes=1), tick=False):
                assert me(token).status_code == 200

        session = row_of(token)
        assert session.ip is None
        assert session.user_agent == USER_AGENT
        assert session.last_activity == T0

    def test_a_code_works_once(self, google: FakeGoogle) -> None:
        pkce = Pkce()
        code = code_for(browser(), google, pkce)
        assert exchange(code, pkce).status_code == 200

        response = exchange(code, pkce)

        assert response.status_code == 400
        assert error_of(response) == {
            "error": "invalid_grant",
            "error_description": "Authorization code not found",
        }
        assert Session.objects.filter(token_hash__isnull=False).count() == 1

    @pytest.mark.parametrize(
        ("overrides", "description"),
        [
            ({"code_verifier": Pkce().verifier}, "Invalid code challenge"),
            ({"client_id": "native"}, "Client ID does not match"),
            ({"redirect_uri": NATIVE_REDIRECT}, "Redirect URI does not match"),
        ],
    )
    def test_a_code_is_bound_to_its_request(
        self, google: FakeGoogle, overrides: dict[str, str], description: str
    ) -> None:
        pkce = Pkce()
        code = code_for(browser(), google, pkce)

        response = exchange(code, pkce, **overrides)

        assert response.status_code == 400
        assert error_of(response) == {
            "error": "invalid_grant",
            "error_description": description,
        }
        assert Session.objects.filter(token_hash__isnull=False).count() == 0
        # A failed exchange uses the code up.
        assert exchange(code, pkce).status_code == 400

    def test_a_code_expires(self, google: FakeGoogle) -> None:
        pkce = Pkce()
        with time_machine.travel(T0, tick=False):
            code = code_for(browser(), google, pkce)

        with time_machine.travel(T0 + timedelta(minutes=30), tick=False):
            response = exchange(code, pkce)

        assert error_of(response)["error"] == "invalid_grant"

    def test_a_client_removed_meanwhile_gets_no_token(self, google: FakeGoogle) -> None:
        pkce = Pkce()
        code = code_for(browser(), google, pkce)
        del clients.clients["spa"]

        response = exchange(code, pkce)

        assert error_of(response) == {
            "error": "invalid_grant",
            "error_description": "Redirect URI is no longer registered for this client",
        }

    @pytest.mark.parametrize(
        "form",
        [
            {},
            {"grant_type": "authorization_code"},
            {"grant_type": "refresh_token", "refresh_token": "x"},
        ],
    )
    def test_a_malformed_request_is_a_json_error(self, form: dict[str, str]) -> None:
        response = post_token(form)

        assert response.status_code == 400
        assert "error" in error_of(response)

    def test_the_password_grant_is_not_offered(self) -> None:
        make_user("person@example.com", password="secret")

        response = post_token(
            {
                "grant_type": "password",
                "client_id": "spa",
                "username": "person@example.com",
                "password": "secret",
            }
        )

        assert response.status_code == 400
        assert error_of(response)["error"] == "unsupported_grant_type"
        assert Session.objects.count() == 0

    def test_a_user_deactivated_before_the_exchange_gets_no_token(
        self, google: FakeGoogle
    ) -> None:
        pkce = Pkce()
        code = code_for(browser(), google, pkce)
        get_user_model()._default_manager.update(is_active=False)

        response = exchange(code, pkce)

        assert response.status_code == 400
        assert error_of(response) == {
            "error": "access_denied",
            "error_description": "This account is inactive.",
        }
        assert Session.objects.filter(token_hash__isnull=False).count() == 0
        assert "before_login" not in sent()

    def test_a_user_deleted_before_the_exchange_gets_no_token(
        self, google: FakeGoogle
    ) -> None:
        pkce = Pkce()
        code = code_for(browser(), google, pkce)
        get_user_model()._default_manager.all().delete()

        response = exchange(code, pkce)

        assert response.status_code == 400
        assert error_of(response)["error"] == "access_denied"
        assert Session.objects.count() == 0


class TestTokenSignals:
    def test_a_first_sign_in_sends_login_signals_at_the_exchange(
        self, google: FakeGoogle
    ) -> None:
        pkce = Pkce()
        code = code_for(browser(), google, pkce)

        assert sent() == [
            "before_authorization",
            "authorization_started",
            "before_callback",
            "before_user_create",
            "before_social_account_create",
            "user_created",
            "social_account_created",
        ]
        signals.events.clear()

        token = exchange(code, pkce).json()["access_token"]

        user = get_user_model()._default_manager.get()
        assert sent() == ["before_login", "after_login"]
        before = payload("before_login")
        assert before["sender"] is get_user_model()
        assert before["provider"] == "google"
        assert (before["user_id"], before["email"]) == (
            str(user.pk),
            "person@gmail.com",
        )
        assert before["request"].path == "/auth/token"
        after = payload("after_login")
        assert (after["provider"], after["user"]) == ("google", user)
        assert row_of(token).user_id == user.pk

    def test_after_login_sees_the_stored_session(self, google: FakeGoogle) -> None:
        seen: list[int] = []
        signals.handlers["after_login"] = lambda **kwargs: seen.append(
            Session.objects.filter(token_hash__isnull=False).count()
        )

        token_for(google)

        assert seen == [1]

    def test_before_login_can_refuse_with_a_json_error(
        self, google: FakeGoogle
    ) -> None:
        # How an application keeps an allow list: a returning user it no
        # longer accepts gets no token, whichever way they sign in.
        token_for(google)
        signals.events.clear()
        signals.handlers["before_login"] = refuse
        pkce = Pkce()
        code = code_for(browser(), google, pkce)

        response = exchange(code, pkce)

        assert response.status_code == 400
        assert error_of(response) == {
            "error": "access_denied",
            "error_description": "Not allowed.",
        }
        assert sent()[-1] == "before_login"
        assert "after_login" not in sent()
        assert Session.objects.filter(token_hash__isnull=False).count() == 1

    def test_a_refusal_without_a_message_still_says_something(
        self, google: FakeGoogle
    ) -> None:
        def refuse_silently(**kwargs: Any) -> None:
            raise PermissionDenied

        signals.handlers["before_login"] = refuse_silently
        pkce = Pkce()
        code = code_for(browser(), google, pkce)

        assert error_of(exchange(code, pkce)) == {
            "error": "access_denied",
            "error_description": "Permission denied",
        }

    def test_a_browser_sign_in_still_refuses_with_django_403(
        self, google: FakeGoogle
    ) -> None:
        connect(make_user("person@gmail.com"))
        signals.handlers["before_login"] = refuse
        client = browser()

        response = sign_in(client, google)

        assert response.status_code == 403
        assert whoami(client)["authenticated"] is False


class TestBearer:
    def test_authenticates_the_tokens_user(self, google: FakeGoogle) -> None:
        token = token_for(google)

        response = me(token)

        user = get_user_model()._default_manager.get()
        assert response.status_code == 200
        assert response.json() == {
            "user_id": str(user.pk),
            "client_id": "spa",
            "session_id": str(row_of(token).public_id),
            # Not a Django login: request.user is whoever the cookie says.
            "django_user": False,
        }

    def test_returns_the_native_user_and_the_session(self, google: FakeGoogle) -> None:
        token = token_for(google)
        request = RequestFactory().get("/api/me", headers=bearer(token))

        authenticated = authenticate_bearer(request)

        assert authenticated is not None
        assert authenticated.user == get_user_model()._default_manager.get()
        assert authenticated.session.native == row_of(token)
        assert authenticated.session.client_id == "spa"
        assert authenticated.session.status == "active"

    @pytest.mark.parametrize(
        "header",
        [
            None,
            "",
            "Bearer",
            "Bearer ",
            "Bearer not-a-token",
            "Basic dXNlcjpwYXNz",
            "Token {token}",
            "{token}",
        ],
    )
    def test_refuses_anything_but_a_valid_bearer_token(
        self, google: FakeGoogle, header: str | None
    ) -> None:
        token = token_for(google)
        headers = (
            {} if header is None else {"Authorization": header.format(token=token)}
        )

        assert app().get("/api/me", headers=headers).status_code == 401

    def test_the_scheme_is_case_insensitive(self, google: FakeGoogle) -> None:
        token = token_for(google)

        response = app().get("/api/me", headers={"Authorization": f"bearer {token}"})

        assert response.status_code == 200

    def test_a_token_is_no_session_cookie(self, google: FakeGoogle) -> None:
        token = token_for(google)
        client = app()
        for name in (settings.SESSION_COOKIE_NAME, "session_id"):
            client.cookies[name] = token

        assert client.get("/api/me").status_code == 401
        assert whoami(client)["authenticated"] is False

    def test_a_tokens_session_key_is_no_session_cookie(
        self, google: FakeGoogle
    ) -> None:
        client = app()
        client.cookies[settings.SESSION_COOKIE_NAME] = row_of(
            token_for(google)
        ).session_key

        assert whoami(client)["authenticated"] is False

    def test_a_browser_session_is_no_bearer_token(self, google: FakeGoogle) -> None:
        client = browser()
        sign_in(client, google)
        session_key = client.cookies[settings.SESSION_COOKIE_NAME].value

        assert me(session_key).status_code == 401

    def test_expires_after_token_max_age(self, google: FakeGoogle) -> None:
        with time_machine.travel(T0, tick=False):
            token = token_for(google)

        with time_machine.travel(T0 + timedelta(days=1), tick=False):
            assert me(token).status_code == 200
        with time_machine.travel(T0 + timedelta(days=1, seconds=1), tick=False):
            assert me(token).status_code == 401

    def test_use_does_not_extend_a_token_by_default(self, google: FakeGoogle) -> None:
        with time_machine.travel(T0, tick=False):
            token = token_for(google)

        with time_machine.travel(T0 + timedelta(hours=23), tick=False):
            assert me(token).status_code == 200

        session = row_of(token)
        assert session.expire_date == T0 + timedelta(days=1)
        assert session.updated_at == T0
        assert session.last_activity == T0 + timedelta(hours=23)

    def test_token_update_age_extends_a_token_in_use(self, google: FakeGoogle) -> None:
        with oauth_server(token_max_age=30 * DAY, token_update_age=DAY):
            with time_machine.travel(T0, tick=False):
                token = token_for(google)

            # Used within a day: not extended yet.
            with time_machine.travel(T0 + timedelta(hours=23), tick=False):
                assert me(token).status_code == 200
            assert row_of(token).expire_date == T0 + timedelta(days=30)

            later = T0 + timedelta(days=20)
            with time_machine.travel(later, tick=False):
                assert me(token).status_code == 200
            session = row_of(token)
            assert session.expire_date == later + timedelta(days=30)
            assert session.updated_at == session.last_activity == later
            assert session.created_at == T0

            # Left unused for longer than its lifetime, it is gone.
            with time_machine.travel(later + timedelta(days=31), tick=False):
                assert me(token).status_code == 401

    def test_records_activity_once_per_interval(self, google: FakeGoogle) -> None:
        with time_machine.travel(T0, tick=False):
            token = token_for(google)

        with time_machine.travel(T0 + timedelta(minutes=4), tick=False):
            assert me(token).status_code == 200
        assert row_of(token).last_activity == T0

        with time_machine.travel(T0 + timedelta(minutes=6), tick=False):
            assert me(token).status_code == 200
        assert row_of(token).last_activity == T0 + timedelta(minutes=6)

    def test_a_deactivated_user_is_refused_and_not_extended(
        self, google: FakeGoogle
    ) -> None:
        with oauth_server(token_update_age=0):
            with time_machine.travel(T0, tick=False):
                token = token_for(google)
            users = get_user_model()._default_manager
            users.update(is_active=False)

            with time_machine.travel(T0 + timedelta(hours=1), tick=False):
                assert me(token).status_code == 401
            session = row_of(token)
            assert session.expire_date == T0 + timedelta(days=1)
            assert session.last_activity == T0

            # The token was not revoked: it works again for a reactivated user.
            users.update(is_active=True)
            with time_machine.travel(T0 + timedelta(hours=2), tick=False):
                assert me(token).status_code == 200

    def test_a_deleted_users_tokens_are_gone(self, google: FakeGoogle) -> None:
        token = token_for(google)

        get_user_model()._default_manager.all().delete()

        assert me(token).status_code == 401
        assert Session.objects.count() == 0

    def test_each_sign_in_gets_a_token_of_its_own(self, google: FakeGoogle) -> None:
        first = token_for(google)
        second = token_for(google)

        assert first != second
        assert me(first).json()["user_id"] == me(second).json()["user_id"]
        assert me(first).json()["session_id"] != me(second).json()["session_id"]


class TestLogout:
    def test_revokes_the_requests_token(self, google: FakeGoogle) -> None:
        token = token_for(google)
        other = token_for(google)

        with time_machine.travel(T0, tick=False):
            response = logout(token)

        assert response.status_code == 204
        assert response.content == b""
        assert "Content-Type" not in response
        assert response.cookies == {}
        assert me(token).status_code == 401
        assert me(other).status_code == 200
        # The row stays, marked revoked, until it would have expired.
        assert row_of(token).revoked_at == T0
        assert row_of(other).revoked_at is None

    def test_needs_no_csrf_token_and_is_a_post(self, google: FakeGoogle) -> None:
        token = token_for(google)

        assert app().get("/auth/logout", headers=bearer(token)).status_code == 405
        assert me(token).status_code == 200

    def test_scope_all_revokes_every_token_of_the_user(
        self, google: FakeGoogle
    ) -> None:
        first = token_for(google)
        second = token_for(google)
        someone_else = token_for(google, Account(sub="other", email="other@gmail.com"))

        response = logout(first, {"scope": "all"})

        assert response.status_code == 204
        assert me(first).status_code == 401
        assert me(second).status_code == 401
        assert me(someone_else).status_code == 200

    def test_scope_all_leaves_browser_sessions_signed_in(
        self, google: FakeGoogle
    ) -> None:
        client = browser()
        sign_in(client, google)
        token = token_for(google)

        logout(token, {"scope": "all"})

        assert whoami(client)["authenticated"] is True

    @pytest.mark.parametrize("token", [None, "not-a-token"])
    def test_without_a_token_to_revoke_it_still_answers_204(
        self, google: FakeGoogle, token: str | None
    ) -> None:
        kept = token_for(google)
        signals.events.clear()

        assert logout(token).status_code == 204
        assert logout(token, {"scope": "all"}).status_code == 204

        assert me(kept).status_code == 200
        assert sent() == []

    def test_a_revoked_token_revokes_nothing_more(self, google: FakeGoogle) -> None:
        token = token_for(google)
        other = token_for(google)
        logout(token)
        signals.events.clear()

        assert logout(token, {"scope": "all"}).status_code == 204

        assert me(other).status_code == 200
        assert sent() == []

    def test_reads_no_cookie(self, google: FakeGoogle) -> None:
        # The view skips CSRF checks, so a cookie must not be able to act.
        token = token_for(google)
        client = app()
        for name in (settings.SESSION_COOKIE_NAME, "session_id"):
            client.cookies[name] = token

        response = client.post("/auth/logout", data="", content_type="text/plain")

        assert response.status_code == 204
        assert me(token).status_code == 200

    def test_does_not_sign_a_browser_out(self, google: FakeGoogle) -> None:
        client = browser()
        sign_in(client, google)
        token = token_for(google)

        response = client.post(
            "/auth/logout", data="", content_type="text/plain", headers=bearer(token)
        )

        assert response.status_code == 204
        assert whoami(client)["authenticated"] is True
        assert me(token).status_code == 401

    @pytest.mark.parametrize("body", ["{", '{"scope": "others"}', "[]"])
    def test_a_malformed_body_is_a_json_error(
        self, google: FakeGoogle, body: str
    ) -> None:
        token = token_for(google)

        response = logout(token, body)

        assert response.status_code == 400
        assert error_of(response)["error"] == "invalid_request"
        assert me(token).status_code == 200

    def test_sends_the_session_signals(self, google: FakeGoogle) -> None:
        token = token_for(google)
        token_for(google)
        user = get_user_model()._default_manager.get()
        session_id = str(row_of(token).public_id)
        signals.events.clear()

        logout(token)

        assert sent() == ["before_session_revoke", "session_revoked"]
        before = payload("before_session_revoke")
        assert before["sender"] is get_user_model()
        assert before["request"].path == "/auth/logout"
        assert "provider" not in before
        assert (before["user_id"], before["scope"], before["session_id"]) == (
            str(user.pk),
            "one",
            session_id,
        )
        after = payload("session_revoked")
        assert (after["user"], after["scope"]) == (user, "one")
        assert (after["session_id"], after["revoked_count"]) == (session_id, 1)

    def test_scope_all_names_no_session_in_its_signals(
        self, google: FakeGoogle
    ) -> None:
        token = token_for(google)
        token_for(google)
        signals.events.clear()

        logout(token, {"scope": "all"})

        before = payload("before_session_revoke")
        assert (before["scope"], before["session_id"]) == ("all", None)
        after = payload("session_revoked")
        assert (after["scope"], after["session_id"]) == ("all", None)
        assert after["revoked_count"] == 2

    def test_before_session_revoke_can_refuse_with_a_json_error(
        self, google: FakeGoogle
    ) -> None:
        token = token_for(google)
        signals.handlers["before_session_revoke"] = refuse

        response = logout(token)

        assert response.status_code == 403
        assert error_of(response) == {
            "error": "access_denied",
            "error_description": "Not allowed.",
        }
        assert me(token).status_code == 200
        assert "session_revoked" not in sent()


class TestTransactions:
    def test_views_opt_out_of_atomic_requests(
        self, google: FakeGoogle, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Django reads ATOMIC_REQUESTS from the connection on each request.
        monkeypatch.setitem(
            connections["default"].settings_dict, "ATOMIC_REQUESTS", True
        )

        token = token_for(google)

        assert me(token).status_code == 200
        assert logout(token).status_code == 204
        assert me(token).status_code == 401

    @pytest.mark.parametrize("path", ["/auth/token", "/auth/logout"])
    def test_enclosing_transaction_is_rejected(self, path: str) -> None:
        with pytest.raises(ImproperlyConfigured, match="transaction.atomic"):
            with transaction.atomic():
                app().post(path, data="", content_type="application/json")

    def test_authenticating_inside_a_transaction_is_allowed(
        self, google: FakeGoogle
    ) -> None:
        # An application's API view may run in a transaction of its own.
        token = token_for(google)

        with transaction.atomic():
            assert me(token).status_code == 200
