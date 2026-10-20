"""The opt-in OAuth server component."""

from dataclasses import dataclass

from ._clients import ClientResolver
from ._tokens import TokenIssuer


@dataclass(frozen=True, kw_only=True)
class OAuthServer:
    """Make Cross Auth an OAuth authorization server for your own clients.

    Passing one mounts ``/{provider}/authorize``, ``/token``,
    ``/{provider}/link`` and ``/{provider}/finalize-link`` for SPA and native
    clients. Without it those routes do not exist.

    ``get_client`` looks up clients at authorization-code and linking checks;
    it returns ``None`` for unknown clients. A static mapping's ``.get`` works.
    Without it these flows reject every client. Password grants do not use
    this lookup.

    ``token_issuer`` mints the token ``/token`` returns. Without it, ``/token``
    issues an opaque session token from ``session_storage``.

    ``password_grant=True`` also accepts the deprecated OAuth password grant at
    ``/token``, warning on each use. It will be removed in 1.0.
    """

    get_client: ClientResolver | None = None
    token_issuer: TokenIssuer | None = None
    password_grant: bool = False
