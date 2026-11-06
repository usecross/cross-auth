"""Credentials stay out of the repr of events and models hooks receive.

A hook, or an error handler, that logs an event must not log a password, a
provider token or an authorization code with it.
"""

from datetime import datetime, timezone
from typing import Any

import pytest

from cross_auth._authorization import AuthRequest, LinkCodeData
from cross_auth._authorization_code import AuthorizationCodeGrantData
from cross_auth._issuer import AuthorizationCodeGrantRequest, PasswordGrantRequest
from cross_auth.hooks import (
    BeforeAuthenticateEvent,
    BeforeOAuthIdTokenEvent,
    BeforeSocialAccountCreateEvent,
    BeforeSocialAccountUpdateEvent,
    SocialAccountSnapshot,
)
from cross_auth.hooks.events import (
    AfterOAuthCallbackEvent,
    AfterTokenAuthorizationCodeEvent,
    AfterTokenPasswordEvent,
)
from cross_auth.models.oauth_token_response import TokenResponse
from cross_auth.social_providers.oauth import CallbackData

from .conftest import SocialAccount, User

SECRET = "sekrit-value-that-must-not-be-logged"


def _token_response() -> TokenResponse:
    return TokenResponse(
        token_type="Bearer",
        access_token=f"access-{SECRET}",
        refresh_token=f"refresh-{SECRET}",
        id_token=f"id-{SECRET}",
        scope="email",
    )


def _password_grant() -> PasswordGrantRequest:
    return PasswordGrantRequest(
        grant_type="password",
        client_id="client",
        client_secret=f"client-{SECRET}",
        username="alice@example.com",
        password=SECRET,
    )


def _code_grant() -> AuthorizationCodeGrantRequest:
    return AuthorizationCodeGrantRequest(
        grant_type="authorization_code",
        client_id="client",
        client_secret=f"client-{SECRET}",
        code=f"code-{SECRET}",
        redirect_uri="http://client.example/cb",
        code_verifier=f"verifier-{SECRET}",
    )


def _social_account_update() -> BeforeSocialAccountUpdateEvent:
    account = SocialAccount(
        id="account",
        user_id="user",
        provider_user_id="fake-user",
        provider="fake",
        access_token=SECRET,
    )
    return BeforeSocialAccountUpdateEvent(
        social_account=SocialAccountSnapshot.of(account),
        user_id="user",
        provider="fake",
        provider_user_id="fake-user",
        access_token=f"access-{SECRET}",
        refresh_token=f"refresh-{SECRET}",
        access_token_expires_at=None,
        refresh_token_expires_at=None,
        scope="email",
        user_info={"id": "fake-user"},
        provider_email="alice@example.com",
        provider_email_verified=True,
        is_login_method=True,
        extra_fields={},
    )


@pytest.mark.parametrize(
    "value",
    [
        BeforeAuthenticateEvent(email="alice@example.com", password=SECRET),
        BeforeOAuthIdTokenEvent(
            provider="google", id_token=SECRET, user_info={"name": SECRET}
        ),
        BeforeSocialAccountCreateEvent(
            user_id="user",
            provider="fake",
            provider_user_id="fake-user",
            access_token=f"access-{SECRET}",
            refresh_token=f"refresh-{SECRET}",
            access_token_expires_at=None,
            refresh_token_expires_at=None,
            scope="email",
            user_info={"id": "fake-user"},
            provider_email="alice@example.com",
            provider_email_verified=True,
            is_login_method=True,
            extra_fields={},
        ),
        _social_account_update(),
        AfterTokenPasswordEvent(
            request=_password_grant(),
            client_id="client",
            username="alice@example.com",
            user=User(
                id="user",
                email="alice@example.com",
                email_verified=True,
                hashed_password=None,
                social_accounts=[],
            ),
            token_response=_token_response(),
        ),
        _password_grant(),
        _code_grant(),
        AfterTokenAuthorizationCodeEvent(
            request=_code_grant(),
            code=f"code-{SECRET}",
            authorization_data=AuthorizationCodeGrantData(
                user_id="user",
                expires_at=datetime.now(tz=timezone.utc),
                client_id="client",
                redirect_uri="http://client.example/cb",
                code_challenge="challenge",
                code_challenge_method="S256",
            ),
            token_response=_token_response(),
        ),
        _token_response(),
        CallbackData(code=SECRET, state="state", error=None),
        LinkCodeData(
            expires_at=datetime.now(tz=timezone.utc),
            client_id="client",
            redirect_uri="http://client.example/cb",
            code_challenge="challenge",
            code_challenge_method="S256",
            user_id="user",
            provider_code=f"code-{SECRET}",
            provider_code_verifier=f"verifier-{SECRET}",
        ),
        AuthRequest(
            flow="session",
            provider_id="fake",
            state="state",
            provider_code_verifier=SECRET,
            browser_binding="binding",
            expires_at=datetime.now(tz=timezone.utc),
        ),
    ],
    ids=lambda value: type(value).__name__,
)
def test_repr_hides_credentials(value: object) -> None:
    for text in (repr(value), str(value)):
        assert text
        assert SECRET not in text


def test_callback_event_hides_the_authorization_code() -> None:
    # Only the repr is under test, so the other fields are placeholders.
    fields: dict[str, Any] = {name: None for name in AfterOAuthCallbackEvent.__slots__}
    fields["authorization_code"] = SECRET
    fields["client_state"] = "state"
    event = AfterOAuthCallbackEvent(**fields)
    assert SECRET not in repr(event)
    assert event.authorization_code == SECRET


def test_hidden_fields_keep_their_values() -> None:
    request = _password_grant()
    assert request.password == SECRET
    event = BeforeAuthenticateEvent(email="alice@example.com", password=SECRET)
    assert event.password == SECRET
