from cross_web import HTTPRequest

from cross_auth import OAuthServer
from cross_auth._context import Context
from cross_auth._issuer import Issuer
from cross_auth._tokens import TokenIssueRequest

from .conftest import TEST_PASSWORD, DeferredSessionStorage, legacy_password_grant


def _password_login(context: Context):
    with legacy_password_grant():
        return Issuer().token(
            HTTPRequest.from_form_data(
                data={
                    "grant_type": "password",
                    "client_id": "test",
                    "username": "test@example.com",
                    "password": TEST_PASSWORD,
                }
            ),
            context,
        )


def test_token_completion_follows_the_storage_that_issued_it(context: Context):
    original = DeferredSessionStorage()
    replacement = DeferredSessionStorage()
    context.session_storage = original
    context.oauth_server = OAuthServer(password_grant=True)
    completed: list[str] = []

    def change_future_storage(event) -> None:
        context.session_storage = replacement

    context.hooks.register_before("login", change_future_storage)
    context.hooks.register_after(
        "token.password", lambda event: completed.append(event.user.id)
    )

    response = _password_login(context)

    assert response.status_code == 200
    assert completed == []
    assert replacement.records == {}
    original.commit()
    assert completed == ["test"]
    replacement.commit()
    assert completed == ["test"]


def test_custom_issuer_completion_does_not_follow_reconfigured_storage(
    context: Context,
):
    replacement = DeferredSessionStorage()
    context.session_storage = replacement
    completed: list[str] = []

    def issue(request: TokenIssueRequest) -> tuple[str, int]:
        context.oauth_server = None
        return "application-token", 60

    context.oauth_server = OAuthServer(token_issuer=issue, password_grant=True)
    context.hooks.register_after(
        "token.password", lambda event: completed.append(event.user.id)
    )

    response = _password_login(context)

    assert response.status_code == 200
    assert completed == ["test"]
    replacement.commit()
    assert completed == ["test"]
