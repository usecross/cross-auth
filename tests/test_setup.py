"""Framework-free setup: no FastAPI imports here (see the isolation test)."""

from collections.abc import Iterator
from typing import Any

import pytest
from cross_web import HTTPRequest

from cross_auth._clients import OAuthClient
from cross_auth._config import Config
from cross_auth._email import normalize_email as default_normalize_email
from cross_auth._issuer import Issuer
from cross_auth._setup import build_auth_setup
from cross_auth._storage import AccountsStorage, SecondaryStorage
from cross_auth.hooks import HookRegistry
from cross_auth.social_providers.github import GitHubProvider
from cross_auth.social_providers.oauth import OAuth2Provider

from .conftest import TEST_PASSWORD, MemorySessionStorage


def _build(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    providers: list[OAuth2Provider] | None = None,
    **kwargs: Any,
):
    return build_auth_setup(
        providers=providers or [],
        secondary_storage=secondary_storage,
        accounts_storage=accounts_storage,
        get_user_from_request=lambda request: None,
        **kwargs,
    )


def test_setup_shares_the_given_objects(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: MemorySessionStorage,
):
    hooks = HookRegistry()
    config: Config = {"session": {"max_age": 60}}

    def resolver(request: HTTPRequest) -> None:
        return None

    def lower(email: str) -> str:
        return email.lower()

    setup = build_auth_setup(
        providers=[],
        secondary_storage=secondary_storage,
        accounts_storage=accounts_storage,
        session_storage=session_storage,
        get_user_from_request=resolver,
        config=config,
        hooks=hooks,
        normalize_email=lower,
        base_url="https://api.example",
        default_next_url="/home",
    )
    context = setup.context

    assert context.secondary_storage is secondary_storage
    assert context.accounts_storage is accounts_storage
    assert context.session_storage is session_storage
    assert context.get_user_from_request is resolver
    assert context.hooks is hooks
    assert context.normalize_email is lower
    assert context.config is config
    assert context.session_config is config["session"]
    assert context.base_url == "https://api.example"
    assert context.default_next_url == "/home"
    assert isinstance(setup.issuer, Issuer)


def test_setup_defaults(secondary_storage, accounts_storage):
    setup = _build(secondary_storage, accounts_storage)

    assert isinstance(setup.context.hooks, HookRegistry)
    assert setup.context.normalize_email is default_normalize_email
    assert setup.context.session_config is None
    assert setup.context.session_storage is None


def test_providers_keep_route_order_and_last_id_wins_for_lookup(
    secondary_storage, accounts_storage
):
    first = GitHubProvider(client_id="first", client_secret="secret")
    second = GitHubProvider(client_id="second", client_secret="secret")
    providers: list[OAuth2Provider] = [first, second]

    setup = _build(secondary_storage, accounts_storage, providers=providers)
    providers.clear()

    assert setup.providers == (first, second)
    assert dict(setup.providers_by_id) == {"github": second}


def test_routes_and_lookup_use_one_provider_snapshot(
    secondary_storage, accounts_storage
):
    first = GitHubProvider(client_id="first", client_secret="secret")
    later = GitHubProvider(client_id="later", client_secret="secret")

    class ChangingProviders(list[OAuth2Provider]):
        def __iter__(self) -> Iterator[OAuth2Provider]:
            yield from super().__iter__()
            # Model a caller changing the input between snapshot and lookup.
            self.append(later)

    providers = ChangingProviders([first])
    setup = _build(secondary_storage, accounts_storage, providers=providers)

    assert len(providers) == 2
    assert setup.providers == (first,)
    assert dict(setup.providers_by_id) == {"github": first}


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"config": {"allowed_client_ids": ["web"]}}, "allowed_client_ids"),
        (
            {
                "config": {"client_redirect_uris": {"web": ["https://a.example/cb"]}},
                "get_client": lambda client_id: None,
            },
            "not both",
        ),
        ({"config": {"session": {"cookies": {"auth": True}}}}, "session_storage"),
    ],
)
def test_setup_rejects_invalid_configuration(
    secondary_storage, accounts_storage, kwargs, message
):
    with pytest.raises(ValueError, match=message):
        _build(secondary_storage, accounts_storage, **kwargs)


def test_setup_validates_static_client_redirects(secondary_storage, accounts_storage):
    with pytest.raises(ValueError):
        _build(
            secondary_storage,
            accounts_storage,
            config={"client_redirect_uris": {"web": ["not a url"]}},
        )


def test_custom_client_resolver_is_used(secondary_storage, accounts_storage):
    client = OAuthClient(client_id="web", redirect_uris=("https://a.example/cb",))
    setup = _build(
        secondary_storage,
        accounts_storage,
        get_client=lambda client_id: client if client_id == "web" else None,
    )

    assert setup.context.get_client("web") is client
    assert setup.context.is_valid_redirect_uri("https://a.example/cb", client_id="web")
    assert setup.context.get_client("other") is None


def test_issuer_runs_against_the_setup_context(
    secondary_storage, accounts_storage, session_storage: MemorySessionStorage
):
    hooks = HookRegistry()
    seen: list[str] = []
    hooks.register_after("token.password", lambda event: seen.append(event.user.id))
    setup = _build(
        secondary_storage,
        accounts_storage,
        session_storage=session_storage,
        hooks=hooks,
        normalize_email=lambda email: email.strip().lower(),
    )

    response = setup.issuer.token(
        HTTPRequest.from_form_data(
            data={
                "grant_type": "password",
                "client_id": "test",
                "username": "  TEST@example.com ",
                "password": TEST_PASSWORD,
            }
        ),
        setup.context,
    )

    assert response.status_code == 200
    assert seen == ["test"]
    assert [record.user_id for record in session_storage.records.values()] == ["test"]


def test_setup_without_broker_has_no_issuer(secondary_storage, accounts_storage):
    setup = _build(secondary_storage, accounts_storage, broker=False)

    assert setup.issuer is None
    assert setup.context.broker_enabled is False
    assert _build(secondary_storage, accounts_storage).context.broker_enabled
