"""``user_can_authenticate`` in the OAuth flows.

The browser callback checks the user it resolved before it issues a session
or an authorization code, so the refusal comes back on the flow's error path.
Linking that makes a provider identity a way to sign in checks the user too,
and so does auto-linking, before it attaches the identity and again once the
identity's after hooks have run. Every check runs
only once the provider identity is verified. A ``CrossAuthException`` the rule
returns is answered as one it raises, with its own status where the response
has one of Cross-Auth's choosing.
"""

from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import respx
from fastapi import FastAPI
from fastapi.testclient import TestClient

from cross_auth import User
from cross_auth._session import create_session
from cross_auth.exceptions import CrossAuthException
from cross_auth.fastapi import CrossAuth
from cross_auth.hooks import AfterOAuthCallbackEvent, AfterSocialAccountCreateEvent
from tests.conftest import SocialAccount

from .conftest import (
    APP_OAUTH_SERVER,
    load_auth_request,
    mock_token_and_userinfo,
    start_provider_auth,
)
from .test_link_flow import _LINK_CODE_VERIFIER, _store_link_code
from .test_token_flow import _AUTHZ_PARAMS

# Not the generic refusal's 403, so a response shows whose status it has.
SUSPENDED = CrossAuthException("account_suspended", "Account suspended", 423)
SUSPENDED_BODY = {
    "error": "account_suspended",
    "error_description": "Account suspended",
}


class Rule:
    """Refuses the user ids in ``refused`` and records each user it checks.

    It refuses with False or, when set, with ``error``: raised, or returned
    with ``returns``.
    """

    def __init__(self) -> None:
        self.refused: set[str] = set()
        self.error: CrossAuthException | None = None
        self.returns = False
        self.checked: list[str] = []

    def __call__(self, user: User) -> bool | CrossAuthException:
        self.checked.append(str(user.id))
        if str(user.id) not in self.refused:
            return True
        if self.error is None:
            return False
        if self.returns:
            return self.error
        raise self.error


@pytest.fixture
def rule() -> Rule:
    return Rule()


@pytest.fixture(params=["raised", "returned"])
def own_error_rule(request: pytest.FixtureRequest, rule: Rule) -> Rule:
    """A rule that refuses with SUSPENDED, which sign-in answers either way."""
    rule.error = SUSPENDED
    rule.returns = request.param == "returned"
    return rule


@pytest.fixture
def linked(accounts_storage) -> SocialAccount:
    """A provider identity that signs the seeded ``test`` user in."""
    account = SocialAccount(
        id="linked",
        user_id="test",
        provider="fake",
        provider_user_id="fake-user-1",
        provider_email="test@example.com",
        provider_email_verified=True,
    )
    accounts_storage.data["test"].social_accounts.append(account)
    return account


def _client(auth: CrossAuth) -> TestClient:
    app = FastAPI()
    app.include_router(auth.router)
    return TestClient(app, follow_redirects=False)


def _callback(client: TestClient, state: str, **params: str):
    return client.get(
        "/fake/callback", params={"code": "provider-code", "state": state, **params}
    )


@respx.mock
def test_session_callback_refuses_before_logging_in(
    build_auth, session_storage, linked, rule
):
    auth = build_auth(user_can_authenticate=rule)
    callbacks: list[AfterOAuthCallbackEvent] = []
    auth.after("oauth.callback")(callbacks.append)
    rule.refused.add("test")
    mock_token_and_userinfo(email="test@example.com")

    with _client(auth) as client:
        _, state = start_provider_auth(client, "/fake/login")
        response = _callback(client, state)

    assert response.status_code == 403
    assert response.json() == {
        "error": "access_denied",
        "error_description": "Sign-in is not allowed",
    }
    assert "session_id" not in response.cookies
    assert session_storage.records == {}
    assert callbacks == []


@respx.mock
def test_session_callback_answers_with_the_rules_own_error(
    build_auth, session_storage, accounts_storage, linked, own_error_rule
):
    auth = build_auth(user_can_authenticate=own_error_rule)
    own_error_rule.refused.add("test")
    mock_token_and_userinfo(email="test@example.com")

    with _client(auth) as client:
        _, state = start_provider_auth(client, "/fake/login")
        response = _callback(client, state)

    assert response.status_code == 423
    assert response.json() == SUSPENDED_BODY
    assert session_storage.records == {}
    assert list(accounts_storage.data) == ["test"]


@respx.mock
def test_session_callback_checks_the_user_once(
    build_auth, session_storage, accounts_storage, rule
):
    auth = build_auth(user_can_authenticate=rule)
    mock_token_and_userinfo(email="new@example.com", provider_user_id="new-1")

    with _client(auth) as client:
        _, state = start_provider_auth(client, "/fake/login")
        response = _callback(client, state)

    assert response.status_code == 302
    created = accounts_storage.find_user_by_email("new@example.com")
    assert created is not None
    # New users are checked like existing ones, once per sign-in.
    assert rule.checked == [str(created.id)]
    assert [record.user_id for record in session_storage.records.values()] == [
        str(created.id)
    ]


@respx.mock
def test_token_callback_refuses_on_the_clients_error_redirect(
    build_auth, secondary_storage, linked, rule
):
    auth = build_auth(user_can_authenticate=rule)
    rule.refused.add("test")
    mock_token_and_userinfo(email="test@example.com")

    with _client(auth) as client:
        _, state = start_provider_auth(client, "/fake/authorize", params=_AUTHZ_PARAMS)
        response = _callback(client, state)

    assert response.status_code == 302
    location = urlparse(response.headers["location"])
    assert f"{location.scheme}://{location.netloc}{location.path}" == (
        "http://client.example/cb"
    )
    assert parse_qs(location.query) == {
        "error": ["access_denied"],
        "error_description": ["Sign-in is not allowed"],
        "state": ["client-csrf-state"],
    }
    assert not [key for key in secondary_storage.data if key.startswith("oauth:code:")]


@respx.mock
def test_token_callback_sends_the_rules_own_error_to_the_client(
    build_auth, secondary_storage, linked, own_error_rule
):
    # An OAuth error redirect carries no status of the exception's own.
    auth = build_auth(user_can_authenticate=own_error_rule)
    own_error_rule.refused.add("test")
    mock_token_and_userinfo(email="test@example.com")

    with _client(auth) as client:
        _, state = start_provider_auth(client, "/fake/authorize", params=_AUTHZ_PARAMS)
        response = _callback(client, state)

    assert response.status_code == 302
    location = urlparse(response.headers["location"])
    assert location.netloc == "client.example"
    assert parse_qs(location.query) == {
        "error": ["account_suspended"],
        "error_description": ["Account suspended"],
        "state": ["client-csrf-state"],
    }
    assert not [key for key in secondary_storage.data if key.startswith("oauth:code:")]


def _auto_linking_auth(build_auth, rule: Rule) -> CrossAuth:
    return build_auth(
        user_can_authenticate=rule,
        config={
            "session": {"cookies": {"auth": True}},
            "account_linking": {"enabled": True},
        },
    )


@pytest.mark.parametrize("refusal", ["false", "returned"])
@respx.mock
def test_auto_linking_gives_a_refused_user_no_new_way_to_sign_in(
    build_auth, session_storage, accounts_storage, rule, refusal
):
    # The user is found by email, so the check runs before the identity is
    # attached, as for linking with allow_login.
    auth = _auto_linking_auth(build_auth, rule)
    rule.refused.add("test")
    if refusal == "returned":
        rule.error = SUSPENDED
        rule.returns = True
    mock_token_and_userinfo(email="test@example.com", provider_user_id="new-1")

    with _client(auth) as client:
        _, state = start_provider_auth(client, "/fake/login")
        response = _callback(client, state)

    if refusal == "returned":
        assert response.status_code == 423
        assert response.json() == SUSPENDED_BODY
    else:
        assert response.status_code == 403
        assert response.json()["error"] == "access_denied"
    assert rule.checked == ["test"]
    assert list(accounts_storage.data) == ["test"]
    assert accounts_storage.data["test"].social_accounts == []
    assert session_storage.records == {}


@respx.mock
def test_auto_linking_attaches_the_identity_for_an_allowed_user(
    build_auth, session_storage, accounts_storage, rule
):
    auth = _auto_linking_auth(build_auth, rule)
    mock_token_and_userinfo(email="test@example.com", provider_user_id="new-1")

    with _client(auth) as client:
        _, state = start_provider_auth(client, "/fake/login")
        response = _callback(client, state)

    assert response.status_code == 302
    [account] = accounts_storage.data["test"].social_accounts
    assert account.provider_user_id == "new-1"
    # Before the identity is attached, and again once its hooks have run.
    assert rule.checked == ["test", "test"]


@respx.mock
def test_auto_linking_checks_again_once_the_identity_is_attached(
    build_auth, session_storage, accounts_storage, rule
):
    # An after hook of the new identity refuses the user, so the sign-in stops
    # there, as it does for a new user.
    auth = _auto_linking_auth(build_auth, rule)

    @auth.after("social_account.create")
    def refuse_the_user(event: AfterSocialAccountCreateEvent) -> None:
        rule.refused.add("test")

    mock_token_and_userinfo(email="test@example.com", provider_user_id="new-1")

    with _client(auth) as client:
        _, state = start_provider_auth(client, "/fake/login")
        response = _callback(client, state)

    assert response.status_code == 403
    assert response.json()["error"] == "access_denied"
    assert rule.checked == ["test", "test"]
    assert session_storage.records == {}


@respx.mock
def test_callback_checks_nothing_before_the_identity_is_verified(
    build_auth, linked, rule
):
    auth = build_auth(user_can_authenticate=rule)
    rule.refused.add("test")
    mock_token_and_userinfo(email="test@example.com")

    with _client(auth) as client:
        _, state = start_provider_auth(client, "/fake/login")
        denied = _callback(client, state, error="access_denied")

    assert denied.status_code == 400
    assert rule.checked == []


def _finalize(client: TestClient, code: str, *, allow_login: bool):
    return client.post(
        "/fake/finalize-link",
        headers={"Authorization": "Bearer test"},
        json={
            "link_code": code,
            "code_verifier": _LINK_CODE_VERIFIER,
            "allow_login": allow_login,
        },
    )


def _linking_auth(build_auth, rule: Rule) -> CrossAuth:
    return build_auth(
        user_can_authenticate=rule,
        config={
            "session": {"cookies": {"auth": True}},
            "account_linking": {"enabled": True},
        },
    )


@respx.mock
def test_finalize_link_refuses_a_new_way_to_sign_in(
    build_auth, secondary_storage, accounts_storage, rule
):
    # The router tests' resolver authenticates the bearer header itself, so
    # the request reaches finalize-link; Cross-Auth's resolver would refuse it.
    auth = _linking_auth(build_auth, rule)
    rule.refused.add("test")
    mock_token_and_userinfo(email="test@example.com", provider_user_id="work-1")

    with _client(auth) as client:
        response = _finalize(
            client, _store_link_code(secondary_storage), allow_login=True
        )

    assert response.status_code == 403
    assert response.json()["error"] == "access_denied"
    assert accounts_storage.data["test"].social_accounts == []


@respx.mock
def test_finalize_link_refuses_with_the_rules_own_error(
    build_auth, secondary_storage, accounts_storage, own_error_rule
):
    auth = _linking_auth(build_auth, own_error_rule)
    own_error_rule.refused.add("test")
    mock_token_and_userinfo(email="test@example.com", provider_user_id="work-1")

    with _client(auth) as client:
        response = _finalize(
            client, _store_link_code(secondary_storage), allow_login=True
        )

    assert response.status_code == 423
    assert response.json() == SUSPENDED_BODY
    assert accounts_storage.data["test"].social_accounts == []


@respx.mock
def test_finalize_link_still_links_a_connection(
    build_auth, secondary_storage, accounts_storage, rule
):
    auth = _linking_auth(build_auth, rule)
    rule.refused.add("test")
    mock_token_and_userinfo(email="test@example.com", provider_user_id="work-1")

    with _client(auth) as client:
        response = _finalize(
            client, _store_link_code(secondary_storage), allow_login=False
        )

    assert response.status_code == 200
    [account] = accounts_storage.data["test"].social_accounts
    assert account.is_login_method is False
    assert rule.checked == []


def _connect_with_login(client: TestClient, secondary_storage):
    # Only framework adapters start a connect flow that enables sign-in.
    started = client.get("/fake/connect", headers={"Authorization": "Bearer test"})
    state = parse_qs(urlparse(started.headers["location"]).query)["state"][0]
    auth_request = load_auth_request(secondary_storage, state)
    secondary_storage.set(
        f"oauth:authorization_request:v2:{state}",
        auth_request.model_copy(update={"allow_login": True}).model_dump_json(),
    )
    return client.get(
        "/fake/callback",
        params={"code": "provider-code", "state": state},
        headers={"Authorization": "Bearer test"},
    )


@respx.mock
def test_connect_refuses_a_new_way_to_sign_in(
    build_auth, secondary_storage, accounts_storage, rule
):
    auth = build_auth(user_can_authenticate=rule)
    rule.refused.add("test")
    mock_token_and_userinfo(email="test@example.com", provider_user_id="work-1")

    with _client(auth) as client:
        response = _connect_with_login(client, secondary_storage)

    assert response.status_code == 403
    assert response.json() == {
        "error": "access_denied",
        "error_description": "Sign-in is not allowed",
    }
    assert accounts_storage.data["test"].social_accounts == []


@respx.mock
def test_connect_refuses_with_the_rules_own_error(
    build_auth, secondary_storage, accounts_storage, own_error_rule
):
    auth = build_auth(user_can_authenticate=own_error_rule)
    own_error_rule.refused.add("test")
    mock_token_and_userinfo(email="test@example.com", provider_user_id="work-1")

    with _client(auth) as client:
        response = _connect_with_login(client, secondary_storage)

    assert response.status_code == 423
    assert response.json() == SUSPENDED_BODY
    assert accounts_storage.data["test"].social_accounts == []


def _default_resolver_responses(auth: CrossAuth, token: str) -> list[httpx.Response]:
    with _client(auth) as client:
        bearer = {"Authorization": f"Bearer {token}"}
        return [
            client.get("/fake/connect", headers=bearer),
            client.delete("/fake/social-accounts", headers=bearer),
            client.post(
                "/fake/link",
                headers=bearer,
                json={
                    "client_id": "app-client",
                    "redirect_uri": "http://client.example/cb",
                    "code_challenge": "challenge",
                    "code_challenge_method": "S256",
                },
            ),
            client.post("/fake/finalize-link", headers=bearer, json={}),
        ]


@pytest.fixture
def default_resolver_auth(
    secondary_storage, accounts_storage, session_storage, fake_provider, rule
) -> CrossAuth:
    return CrossAuth(
        providers=[fake_provider],
        storage=secondary_storage,
        accounts_storage=accounts_storage,
        session_storage=session_storage,
        oauth_server=APP_OAUTH_SERVER,
        config={"account_linking": {"enabled": True}},
        user_can_authenticate=rule,
    )


def test_routes_answer_with_the_rules_error_from_the_default_resolver(
    default_resolver_auth, session_storage, rule
):
    token, _ = create_session("test", session_storage)
    rule.refused.add("test")
    rule.error = SUSPENDED

    responses = _default_resolver_responses(default_resolver_auth, token)

    assert [response.status_code for response in responses] == [423] * 4
    assert {response.json()["error"] for response in responses} == {"account_suspended"}

    rule.error = None
    with _client(default_resolver_auth) as client:
        refused = client.get(
            "/fake/connect", headers={"Authorization": f"Bearer {token}"}
        )
    assert refused.status_code == 401


def test_routes_treat_a_returned_refusal_as_no_session(
    default_resolver_auth, session_storage, rule
):
    # The default resolver is a session use: a returned refusal signs the
    # user out quietly, as False does.
    token, _ = create_session("test", session_storage)
    rule.refused.add("test")
    rule.error = SUSPENDED
    rule.returns = True

    responses = _default_resolver_responses(default_resolver_auth, token)

    assert [response.status_code for response in responses] == [401] * 4
    assert {response.json()["error"] for response in responses} == {"unauthorized"}
