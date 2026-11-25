"""The opt-in OAuth server component."""

from dataclasses import dataclass
from urllib.parse import urlsplit

from ._clients import ClientResolver
from ._tokens import TokenIssuer


@dataclass(frozen=True, kw_only=True)
class DeviceGrant:
    """Settings of the OAuth 2.0 Device Authorization Grant (RFC 8628).

    ``verification_uri`` is the application's own page where the user enters
    the code the device shows and approves the request; Cross Auth does not
    serve that page. ``expires_in`` is how long, in seconds, a request waits
    for the user, and ``interval`` how many seconds the device waits between
    polls of ``/token``.
    """

    verification_uri: str
    expires_in: int = 900
    interval: int = 5

    def __post_init__(self) -> None:
        parsed = urlsplit(self.verification_uri)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError("DeviceGrant.verification_uri must be an absolute URL")
        if parsed.fragment:
            raise ValueError("DeviceGrant.verification_uri must not have a fragment")
        for name, value in (
            ("expires_in", self.expires_in),
            ("interval", self.interval),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"DeviceGrant.{name} must be a positive int")


@dataclass(frozen=True, kw_only=True)
class OAuthServer:
    """Make Cross Auth an OAuth authorization server for your own clients.

    Passing one mounts ``/{provider}/authorize``, ``/token``,
    ``/{provider}/link`` and ``/{provider}/finalize-link`` for SPA and native
    clients. Without it those routes do not exist.

    ``get_client`` looks up clients at authorization-code, device and linking
    checks; it returns ``None`` for unknown clients. A static mapping's
    ``.get`` works. Without it these flows reject every client. Password
    grants do not use this lookup.

    ``token_issuer`` mints the token ``/token`` returns. Without it, ``/token``
    issues an opaque session token from ``session_storage``.

    ``device`` turns on the device authorization grant for CLIs and other
    input-constrained clients: ``POST /device/code`` starts a request, the
    signed-in user approves it, and the device polls ``/token`` for its token.

    ``password_grant=True`` also accepts the deprecated OAuth password grant at
    ``/token``, warning on each use. It will be removed in 1.0.
    """

    get_client: ClientResolver | None = None
    token_issuer: TokenIssuer | None = None
    device: DeviceGrant | None = None
    password_grant: bool = False
