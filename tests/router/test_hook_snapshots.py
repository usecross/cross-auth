"""Before hooks receive read-only views of providers, users and social accounts.

Hooks used to receive the live provider and the storage-backed user and
social-account objects, so an in-place change could reach storage or the
provider configuration even when a hook then denied the operation. They now
receive frozen snapshots: assigning to one raises ``FrozenInstanceError``, and
returning a changed snapshot raises ``ValueError`` (or ``TypeError`` for events
that do not accept returned events). The raw ``id``, ``email`` and
``email_verified`` provider claims in ``user_info`` are protected the same way.

These guarantees cover the data passed to hooks. Hooks are trusted application
code; one that changes globals or calls storage directly is not sandboxed.
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable, Iterator
from dataclasses import FrozenInstanceError, replace
from typing import Any

import pytest
import respx
from httpx import Response

from cross_auth.exceptions import CrossAuthException
from cross_auth.fastapi import CrossAuth
from cross_auth.social_providers.oauth import UserInfo, ValidatedUserInfo
from tests.conftest import TEST_PASSWORD, MemoryAccountsStorage, MemorySessionStorage
from tests.conftest import SocialAccount

from .conftest import FakeProvider, mock_token_and_userinfo, start_provider_auth
from .test_identity_hooks import (
    _add_other_user,
    _all_social_accounts,
    _client,
    _connect,
    _finalize_link,
    _link_code,
    _start_link,
)

_AUTHZ_PARAMS = {
    "client_id": "app-client",
    "redirect_uri": "http://client.example/cb",
    "state": "client-state",
    "response_type": "code",
    "code_challenge": "client-challenge",
    "code_challenge_method": "S256",
}


def _run(call: Callable[[], Response]) -> Response | Exception:
    # Returned rather than raised so each test checks storage first and only
    # then how the request failed.
    try:
        return call()
    except Exception as exc:
        return exc


@contextlib.contextmanager
def _attempt(*, deny: bool) -> Iterator[None]:
    """Run a hook's change; with ``deny`` swallow its failure and deny instead,
    as a policy hook that tries a change and then rejects the operation would."""
    if not deny:
        yield
        return
    with contextlib.suppress(FrozenInstanceError):
        yield
    raise CrossAuthException("access_denied", "Denied", 403)


def _assert_rejected(result: Response | Exception, *, deny: bool) -> None:
    if deny:
        assert isinstance(result, Response), result
        assert result.status_code >= 300
        if result.status_code < 400:
            assert "error=access_denied" in result.headers["location"]
        else:
            assert result.json()["error"] == "access_denied"
    else:
        assert isinstance(result, FrozenInstanceError), result


_DENY = pytest.mark.parametrize("deny", [False, True], ids=["assign", "assign_deny"])


def _assert_provider_unchanged(provider: FakeProvider, trust_email: bool) -> None:
    assert "id" not in vars(provider)
    assert provider.id == "fake"
    assert provider.trust_email is trust_email


# --- social_account.update ------------------------------------------------


@_DENY
@pytest.mark.parametrize(
    ("field", "value"),
    [("user_id", "other"), ("id", "other-account"), ("is_login_method", True)],
)
@respx.mock
def test_social_account_update_hook_cannot_change_the_stored_account(
    auth: CrossAuth,
    accounts_storage: MemoryAccountsStorage,
    deny: bool,
    field: str,
    value: object,
):
    _add_other_user(accounts_storage)
    mock_token_and_userinfo(email="test@example.com", provider_user_id="connect-id")
    with _client(auth) as client:
        assert _connect(client).status_code == 302
        [account] = accounts_storage.data["test"].social_accounts
        original = (account.id, account.user_id, account.is_login_method)
        effects: list[object] = []
        auth.after("social_account.update")(effects.append)

        @auth.before("social_account.update")
        def change_account(event) -> None:
            with _attempt(deny=deny):
                # ``field`` is parametrized.
                setattr(event.social_account, field, value)

        result = _run(lambda: _connect(client))

    assert (account.id, account.user_id, account.is_login_method) == original
    assert accounts_storage.data["test"].social_accounts == [account]
    assert accounts_storage.data["other"].social_accounts == []
    assert effects == []
    _assert_rejected(result, deny=deny)


# --- oauth.callback provider ------------------------------------------------


@_DENY
@respx.mock
def test_callback_hook_cannot_change_the_provider_id(
    auth: CrossAuth,
    accounts_storage: MemoryAccountsStorage,
    session_storage: MemorySessionStorage,
    fake_provider: FakeProvider,
    deny: bool,
):
    @auth.before("oauth.callback")
    def change_provider(event) -> None:
        with _attempt(deny=deny):
            event.provider.id = "other-provider"

    effects: list[object] = []
    auth.before("login")(effects.append)
    auth.after("oauth.callback")(effects.append)

    mock_token_and_userinfo(email="new@example.com", provider_user_id="new-id")
    with _client(auth) as client:
        _, state = start_provider_auth(client, "/fake/login")
        result = _run(
            lambda: client.get("/fake/callback", params={"code": "c", "state": state})
        )

    _assert_provider_unchanged(fake_provider, trust_email=True)
    assert list(accounts_storage.data) == ["test"]
    assert session_storage.records == {}
    assert effects == []
    _assert_rejected(result, deny=deny)


@_DENY
@respx.mock
def test_callback_hook_cannot_trust_the_provider_email(
    build_auth,
    accounts_storage: MemoryAccountsStorage,
    session_storage: MemorySessionStorage,
    deny: bool,
):
    provider = FakeProvider(
        client_id="fake-client-id", client_secret="fake-secret", trust_email=False
    )
    auth = build_auth(providers=[provider])

    @auth.before("oauth.callback")
    def trust_email(event) -> None:
        with _attempt(deny=deny):
            event.provider.trust_email = True

    # An unverified email of an existing user must not auto-link.
    mock_token_and_userinfo(
        email="test@example.com", email_verified=False, provider_user_id="new-id"
    )
    with _client(auth) as client:
        _, state = start_provider_auth(client, "/fake/login")
        result = _run(
            lambda: client.get("/fake/callback", params={"code": "c", "state": state})
        )

    _assert_provider_unchanged(provider, trust_email=False)
    assert _all_social_accounts(accounts_storage) == []
    assert session_storage.records == {}
    _assert_rejected(result, deny=deny)


@pytest.mark.parametrize(
    "changes",
    [{"id": "other-provider"}, {"trust_email": False}],
    ids=["id", "trust_email"],
)
@respx.mock
def test_callback_hook_cannot_return_a_different_provider(
    auth: CrossAuth,
    accounts_storage: MemoryAccountsStorage,
    session_storage: MemorySessionStorage,
    changes: dict[str, Any],
):
    auth.before("oauth.callback")(
        lambda event: replace(event, provider=replace(event.provider, **changes))
    )

    mock_token_and_userinfo(email="new@example.com", provider_user_id="new-id")
    with _client(auth) as client:
        _, state = start_provider_auth(client, "/fake/login")
        with pytest.raises(ValueError, match="cannot change the provider"):
            client.get("/fake/callback", params={"code": "c", "state": state})

    assert list(accounts_storage.data) == ["test"]
    assert session_storage.records == {}


@_DENY
def test_authorize_hook_cannot_change_the_provider(
    auth: CrossAuth, fake_provider: FakeProvider, secondary_storage, deny: bool
):
    @auth.before("oauth.authorize")
    def change_provider(event) -> None:
        with _attempt(deny=deny):
            event.provider.id = "other-provider"

    with _client(auth) as client:
        result = _run(lambda: client.get("/fake/authorize", params=_AUTHZ_PARAMS))

    _assert_provider_unchanged(fake_provider, trust_email=True)
    assert not any(key.startswith("oauth:") for key in secondary_storage.data)
    _assert_rejected(result, deny=deny)


# --- signed-in users ---------------------------------------------------------


@_DENY
def test_link_hook_cannot_change_the_signed_in_user(
    build_auth, accounts_storage: MemoryAccountsStorage, secondary_storage, deny: bool
):
    auth = build_auth(config={"account_linking": {"enabled": True}})
    user = accounts_storage.data["test"]

    @auth.before("oauth.link")
    def change_user(event) -> None:
        with _attempt(deny=deny):
            event.user.id = "other"

    effects: list[object] = []
    auth.after("oauth.link")(effects.append)

    with _client(auth) as client:
        result = _run(lambda: _link_response(client))

    assert user.id == "test"
    assert not any(key.startswith("oauth:") for key in secondary_storage.data)
    assert effects == []
    _assert_rejected(result, deny=deny)


def _link_response(client) -> Response:
    return client.post(
        "/fake/link",
        headers={"Authorization": "Bearer test"},
        json={
            "redirect_uri": "http://client.example/cb",
            "code_challenge": "n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
            "code_challenge_method": "S256",
            "client_id": "app-client",
        },
    )


@_DENY
@respx.mock
def test_finalize_link_hook_cannot_change_the_signed_in_user(
    build_auth, accounts_storage: MemoryAccountsStorage, deny: bool
):
    auth = build_auth(config={"account_linking": {"enabled": True}})
    user = accounts_storage.data["test"]
    _add_other_user(accounts_storage)

    @auth.before("oauth.finalize_link")
    def change_user(event) -> None:
        with _attempt(deny=deny):
            event.user.id = "other"

    effects: list[object] = []
    auth.before("social_account.create")(effects.append)
    auth.after("oauth.finalize_link")(effects.append)

    mock_token_and_userinfo(email="test@example.com", provider_user_id="linked-id")
    with _client(auth) as client:
        link_code = _link_code(client)
        result = _run(lambda: _finalize_link(client, link_code))

    assert user.id == "test"
    assert _all_social_accounts(accounts_storage) == []
    assert effects == []
    _assert_rejected(result, deny=deny)


@_DENY
def test_password_hook_cannot_change_the_user(
    auth: CrossAuth,
    accounts_storage: MemoryAccountsStorage,
    session_storage: MemorySessionStorage,
    deny: bool,
):
    user = accounts_storage.data["test"]
    other = _add_other_user(accounts_storage)

    @auth.before("token.password")
    def change_user(event) -> None:
        with _attempt(deny=deny):
            event.user.id = other.id

    effects: list[object] = []
    auth.before("login")(effects.append)
    auth.after("token.password")(effects.append)

    with _client(auth) as client:
        result = _run(lambda: _password_grant(client))

    assert user.id == "test"
    assert session_storage.records == {}
    assert effects == []
    if deny:
        assert isinstance(result, Response)
        assert result.status_code == 400
        assert result.json()["error"] == "access_denied"
    else:
        assert isinstance(result, FrozenInstanceError), result


def _password_grant(client) -> Response:
    return client.post(
        "/token",
        data={
            "grant_type": "password",
            "client_id": "app-client",
            "username": "test@example.com",
            "password": TEST_PASSWORD,
        },
    )


@_DENY
@pytest.mark.parametrize("target", ["user", "social_account"])
def test_disconnect_hook_cannot_change_the_user_or_account(
    auth: CrossAuth, accounts_storage: MemoryAccountsStorage, deny: bool, target: str
):
    user = accounts_storage.data["test"]
    account = SocialAccount(
        id="fake-account", user_id="test", provider="fake", provider_user_id="fake-1"
    )
    user.social_accounts.append(account)
    _add_other_user(accounts_storage)

    def mutate(event) -> None:
        with _attempt(deny=deny):
            if target == "user":
                event.user.id = "other"
            else:
                event.social_account.user_id = "other"

    auth.before("oauth.disconnect")(mutate)
    with _client(auth) as client:
        result = _run(
            lambda: client.delete(
                "/fake/social-accounts", headers={"Authorization": "Bearer test"}
            )
        )

    assert user.id == "test"
    assert account.user_id == "test"
    assert user.social_accounts == [account]
    _assert_rejected(result, deny=deny)


# --- replacement events that are not accepted -------------------------------


def test_link_and_password_hooks_cannot_return_replacement_events(
    build_auth, accounts_storage: MemoryAccountsStorage, secondary_storage
):
    auth = build_auth(config={"account_linking": {"enabled": True}})
    other = _add_other_user(accounts_storage)
    auth.before("oauth.link")(lambda event: replace(event, user=other))
    auth.before("token.password")(lambda event: replace(event, user=other))
    logins: list[object] = []
    auth.before("login")(logins.append)

    with _client(auth) as client:
        with pytest.raises(TypeError, match="oauth.link before hooks must return None"):
            _link_response(client)
        with pytest.raises(
            TypeError, match="token.password before hooks must return None"
        ):
            _password_grant(client)

    assert not any(key.startswith("oauth:") for key in secondary_storage.data)
    assert logins == []


# --- numeric primary keys ----------------------------------------------------


def test_link_hook_sees_the_original_numeric_user_id(
    build_auth, accounts_storage: MemoryAccountsStorage, secondary_storage
):
    auth = build_auth(config={"account_linking": {"enabled": True}})
    user = accounts_storage.data["test"]
    user.id = 1  # ty: ignore[invalid-assignment]
    seen: list[object] = []

    @auth.before("oauth.link")
    def change_id_type(event) -> None:
        seen.append(event.user.id)
        with contextlib.suppress(FrozenInstanceError):
            event.user.id = "1"

    with _client(auth) as client:
        state = _start_link(client)

    assert seen == [1]
    assert user.id == 1
    # Stringified only where the link request is stored.
    stored = secondary_storage.get(f"oauth:authorization_request:v2:{state}")
    assert stored is not None and '"user_id":"1"' in stored


@respx.mock
def test_finalize_link_hook_cannot_return_a_string_for_a_numeric_user_id(
    build_auth, accounts_storage: MemoryAccountsStorage
):
    auth = build_auth(config={"account_linking": {"enabled": True}})
    user = accounts_storage.data["test"]
    user.id = 1  # ty: ignore[invalid-assignment]
    auth.before("oauth.finalize_link")(
        lambda event: replace(event, user=replace(event.user, id=str(event.user.id)))
    )

    mock_token_and_userinfo(email="test@example.com", provider_user_id="linked-id")
    with _client(auth) as client:
        link_code = _link_code(client)
        with pytest.raises(ValueError, match="cannot change the user"):
            _finalize_link(client, link_code)

    assert user.id == 1
    assert _all_social_accounts(accounts_storage) == []


# --- raw identity claims in user_info ---------------------------------------


_RAW_CLAIM_CHANGES = pytest.mark.parametrize(
    ("key", "value"),
    [
        ("id", "test"),
        ("email", "victim@example.com"),
        ("email_verified", False),
        ("id", None),
    ],
    ids=["id", "email", "email_verified", "remove_id"],
)


def _change_raw_claim(user_info: dict[str, Any], key: str, value: object) -> None:
    if value is None:
        del user_info[key]
    else:
        user_info[key] = value


def _raw_claim_hook(key: str, value: object, *, in_place: bool) -> Callable[[Any], Any]:
    def hook(event):
        if in_place:
            _change_raw_claim(event.user_info, key, value)
            return None
        user_info = dict(event.user_info)
        _change_raw_claim(user_info, key, value)
        return replace(event, user_info=user_info)

    return hook


_IN_PLACE = pytest.mark.parametrize(
    "in_place", [True, False], ids=["in_place", "replacement"]
)


@_IN_PLACE
@_RAW_CLAIM_CHANGES
@pytest.mark.parametrize("event_name", ["oauth.callback", "user.create"])
@respx.mock
def test_signup_hooks_cannot_rewrite_raw_identity_claims(
    auth: CrossAuth,
    accounts_storage: MemoryAccountsStorage,
    session_storage: MemorySessionStorage,
    event_name,
    key: str,
    value: object,
    in_place: bool,
):
    # The test adapter derives the new user's ID from ``user_info["id"]``, as a
    # custom adapter may; an ``id`` rewrite would replace the seeded user.
    seeded = accounts_storage.data["test"]
    auth.before(event_name)(_raw_claim_hook(key, value, in_place=in_place))
    effects: list[object] = []
    auth.before("login")(effects.append)
    auth.after("user.create")(effects.append)

    mock_token_and_userinfo(email="new@example.com", provider_user_id="new-id")
    with _client(auth) as client:
        _, state = start_provider_auth(client, "/fake/login")
        result = _run(
            lambda: client.get("/fake/callback", params={"code": "c", "state": state})
        )

    assert accounts_storage.data == {"test": seeded}
    assert seeded.email == "test@example.com"
    assert session_storage.records == {}
    assert effects == []
    assert isinstance(result, ValueError), result
    assert "user_info id, email or email_verified" in str(result)


@_IN_PLACE
@_RAW_CLAIM_CHANGES
@pytest.mark.parametrize(
    "event_name", ["social_account.create", "social_account.update"]
)
@respx.mock
def test_social_account_hooks_cannot_rewrite_raw_identity_claims(
    auth: CrossAuth,
    accounts_storage: MemoryAccountsStorage,
    monkeypatch: pytest.MonkeyPatch,
    event_name,
    key: str,
    value: object,
    in_place: bool,
):
    mock_token_and_userinfo(email="test@example.com", provider_user_id="connect-id")
    with _client(auth) as client:
        if event_name == "social_account.update":
            assert _connect(client).status_code == 302
        writes: list[object] = []
        for method in ("create_social_account", "update_social_account"):
            monkeypatch.setattr(
                accounts_storage,
                method,
                lambda *args, **kwargs: writes.append(kwargs["user_info"]),
            )
        auth.before(event_name)(_raw_claim_hook(key, value, in_place=in_place))
        result = _run(lambda: _connect(client))

    assert writes == []
    assert isinstance(result, ValueError), result
    assert "user_info id, email or email_verified" in str(result)


@_IN_PLACE
@_RAW_CLAIM_CHANGES
@respx.mock
def test_finalize_link_hook_cannot_rewrite_raw_identity_claims(
    build_auth,
    accounts_storage: MemoryAccountsStorage,
    key: str,
    value: object,
    in_place: bool,
):
    auth = build_auth(config={"account_linking": {"enabled": True}})
    auth.before("oauth.finalize_link")(_raw_claim_hook(key, value, in_place=in_place))
    effects: list[object] = []
    auth.before("social_account.create")(effects.append)

    mock_token_and_userinfo(email="test@example.com", provider_user_id="linked-id")
    with _client(auth) as client:
        link_code = _link_code(client)
        result = _run(lambda: _finalize_link(client, link_code))

    assert effects == []
    assert _all_social_accounts(accounts_storage) == []
    assert isinstance(result, ValueError), result
    assert "user_info id, email or email_verified" in str(result)


class _MappedClaimsProvider(FakeProvider):
    """A custom provider whose subject is not the raw ``id`` claim."""

    def validate_user_info(self, user_info: UserInfo) -> ValidatedUserInfo:
        return ValidatedUserInfo(
            email=user_info["email"],
            provider_user_id=f"mapped:{user_info['id']}",
            email_verified=user_info["email_verified"],
        )


@respx.mock
def test_custom_claim_mapping_and_profile_metadata_keep_working(
    build_auth,
    accounts_storage: MemoryAccountsStorage,
    session_storage: MemorySessionStorage,
):
    provider = _MappedClaimsProvider(
        client_id="fake-client-id", client_secret="fake-secret"
    )
    auth = build_auth(providers=[provider])
    seen: list[tuple[str, Any, str | None]] = []

    @auth.before("oauth.callback")
    def add_profile(event):
        seen.append(("oauth.callback", event.provider.id, event.provider.trust_email))
        event.user_info["name"] = "Alice"
        return replace(event, user_info={**event.user_info, "picture": "a.png"})

    @auth.before("user.create")
    def full_name(event):
        seen.append(("user.create", event.user_info["id"], event.user_info["name"]))
        return replace(event, extra_fields={"full_name": event.user_info["name"]})

    mock_token_and_userinfo(email="alice@example.com", provider_user_id="alice")
    with _client(auth) as client:
        _, state = start_provider_auth(client, "/fake/login")
        resp = client.get("/fake/callback", params={"code": "c", "state": state})

    assert resp.status_code == 302
    assert seen == [("oauth.callback", "fake", True), ("user.create", "alice", "Alice")]
    assert accounts_storage.last_user_extra_fields == {"full_name": "Alice"}
    [account] = accounts_storage.data["alice"].social_accounts
    assert account.provider_user_id == "mapped:alice"
    assert len(session_storage.records) == 1
