"""Framework-independent Cross Auth setup.

Builds the shared ``Context``, provider registry, and (with the OAuth server)
token ``Issuer`` once so framework adapters (the FastAPI ``AuthRouter`` and
``CrossAuth`` facade today) route against the same objects instead of resolving
their own copies.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass

from cross_web import HTTPRequest

from ._clients import ClientResolver
from ._config import Config
from ._context import Context
from ._issuer import Issuer
from ._storage import AccountsStorage, SecondaryStorage, SessionStorage, User
from ._tokens import TokenIssuer
from .hooks import HookRegistry
from .social_providers.oauth import OAuth2Provider


@dataclass(frozen=True, eq=False)
class AuthSetup:
    context: Context
    # Registration order, used for routes. Duplicate ids are kept as given.
    providers: tuple[OAuth2Provider, ...]
    # Lookup by id for headless operations; the last provider with an id wins.
    providers_by_id: Mapping[str, OAuth2Provider]
    # The OAuth server's token endpoint; None when the OAuth server is disabled.
    issuer: Issuer | None


def build_auth_setup(
    *,
    providers: list[OAuth2Provider],
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    get_user_from_request: Callable[[HTTPRequest], User | None],
    session_storage: SessionStorage | None = None,
    token_issuer: TokenIssuer | None = None,
    base_url: str | None = None,
    config: Config | None = None,
    default_next_url: str = "/",
    hooks: HookRegistry | None = None,
    normalize_email: Callable[[str], str] | None = None,
    get_client: ClientResolver | None = None,
    oauth_server: bool = True,
) -> AuthSetup:
    context = Context(
        secondary_storage=secondary_storage,
        accounts_storage=accounts_storage,
        session_storage=session_storage,
        token_issuer=token_issuer,
        get_user_from_request=get_user_from_request,
        base_url=base_url,
        config=config,
        default_next_url=default_next_url,
        hooks=hooks,
        normalize_email=normalize_email,
        get_client=get_client,
        oauth_server=oauth_server,
    )
    registered_providers = tuple(providers)
    return AuthSetup(
        context=context,
        providers=registered_providers,
        providers_by_id={provider.id: provider for provider in registered_providers},
        issuer=Issuer() if oauth_server else None,
    )
