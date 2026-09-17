"""OAuth client registration and exact redirect matching."""

import re
from collections.abc import Callable
from typing import Literal, Self
from urllib.parse import SplitResult, urlsplit

from pydantic import (
    AnyUrl,
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
    TypeAdapter,
    model_validator,
)

_HTTP_URL = TypeAdapter(HttpUrl)
_URL = TypeAdapter(AnyUrl)

_PRIVATE_SCHEME = re.compile(
    r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*(?:\.[a-z0-9]+(?:-[a-z0-9]+)*)+",
    re.IGNORECASE,
)
_LOOPBACK = re.compile(
    r"(http://(?:127\.0\.0\.1|\[::1\]))(?::[0-9]+)?([/?].*|)", re.IGNORECASE
)


def _parse_redirect(uri: str, application_type: str) -> SplitResult:
    if not uri.isascii() or "#" in uri:
        raise ValueError("Redirect URI must be ASCII without fragments")

    parsed = urlsplit(uri)
    adapter = _HTTP_URL if parsed.scheme in ("http", "https") else _URL

    # Strict validation rejects malformed syntax instead of repairing it.
    # Keep the original URI for matching because Pydantic normalizes URLs.
    adapter.validate_python(uri, strict=True)

    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Redirect URI must not contain user information")

    if parsed.scheme in ("http", "https"):
        if not parsed.hostname or "*" in parsed.hostname or "%" in parsed.netloc:
            raise ValueError(
                "Redirect URI requires a literal hostname without wildcards"
            )
        if parsed.netloc.endswith(":"):
            raise ValueError("Redirect URI port must not be empty")
        if (
            application_type == "native"
            and parsed.scheme == "http"
            and not _LOOPBACK.fullmatch(uri)
        ):
            raise ValueError("Native HTTP redirects require 127.0.0.1 or [::1]")
        return parsed

    if (
        application_type != "native"
        or not _PRIVATE_SCHEME.fullmatch(parsed.scheme)
        or parsed.netloc
        or not uri.partition(":")[2].startswith("/")
        or uri.partition(":")[2].startswith("//")
    ):
        raise ValueError(
            "Redirect URI requires HTTP(S) or a native reverse-domain scheme:/path"
        )
    return parsed


class OAuthClient(BaseModel):
    """Registered broker client. Native loopback redirects may vary only by port.

    Private-use native schemes must follow reverse-domain notation and have
    no authority. Claimed HTTPS redirects must be verified by the application
    platform; registering a URL here does not establish domain ownership.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    client_id: str = Field(min_length=1)
    redirect_uris: tuple[str, ...]
    application_type: Literal["web", "native"] = "web"

    @model_validator(mode="after")
    def validate_redirects(self) -> Self:
        for uri in self.redirect_uris:
            _parse_redirect(uri, self.application_type)
        return self

    def check_redirect_uri(self, uri: str) -> bool:
        """Match original URI strings without decoding or normalizing them."""
        try:
            parsed = _parse_redirect(uri, self.application_type)
        except (ValueError, UnicodeError):
            return False

        if uri in self.redirect_uris:
            return True
        if self.application_type != "native" or parsed.scheme != "http":
            return False

        requested = _LOOPBACK.fullmatch(uri)
        assert requested is not None
        return any(
            registered is not None and registered.groups() == requested.groups()
            for registered in (
                _LOOPBACK.fullmatch(value) for value in self.redirect_uris
            )
        )


ClientResolver = Callable[[str], OAuthClient | None]
