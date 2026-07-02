from collections.abc import Callable
from urllib.parse import urlparse

from cross_web import HTTPRequest, Cookie

from ._config import Config
from ._email import normalize_email as _default_normalize_email
from ._session import (
    SessionConfig,
    SessionMetadata,
    _get_header,
    create_session,
    make_session_cookie,
    resolve_config,
)
from ._storage import (
    AccountsStorage,
    SecondaryStorage,
    SessionRecord,
    SessionStorage,
    User,
)
from ._tokens import TokenIssueRequest, TokenIssuer
from .exceptions import CrossAuthException
from .hooks import HookRegistry
from .utils._is_same_host import is_same_host


class Context:
    def __init__(
        self,
        secondary_storage: SecondaryStorage,
        accounts_storage: AccountsStorage,
        # TODO: this doesn't allow to use the library as an Identity Provider
        trusted_origins: list[str],
        get_user_from_request: Callable[[HTTPRequest], User | None],
        session_storage: SessionStorage | None = None,
        token_issuer: TokenIssuer | None = None,
        base_url: str | None = None,
        config: Config | None = None,
        default_next_url: str = "/",
        hooks: HookRegistry | None = None,
        normalize_email: Callable[[str], str] | None = None,
    ):
        self.secondary_storage = secondary_storage
        self.accounts_storage = accounts_storage
        self.session_storage = session_storage
        self.trusted_origins = trusted_origins
        self.get_user_from_request = get_user_from_request
        self.token_issuer = token_issuer
        self.base_url = base_url
        # Applied to every user lookup/creation by email (not to the raw
        # provider_email stored on social accounts).
        self.normalize_email = (
            normalize_email if normalize_email is not None else _default_normalize_email
        )
        self.config: Config = config if config is not None else {}
        self.session_config: SessionConfig | None = self.config.get("session")
        self.default_next_url = default_next_url
        self.hooks = hooks if hooks is not None else HookRegistry()

        if self.cookie_auth_enabled and session_storage is None:
            raise ValueError(
                "config['session']['cookies']['auth'] is enabled but no "
                "session_storage was provided"
            )

    @property
    def cookie_auth_enabled(self) -> bool:
        cookies = (self.config.get("session") or {}).get("cookies") or {}
        return cookies.get("auth", False)

    def create_session(
        self,
        user_id: str,
        metadata: SessionMetadata | None = None,
    ) -> tuple[str, SessionRecord]:
        session_storage = self.session_storage
        if session_storage is None:
            raise RuntimeError("Session flow not configured for this deployment")

        resolved = resolve_config(self.session_config)
        return create_session(
            user_id,
            session_storage,
            max_age=resolved["max_age"],
            metadata=metadata,
            token_hasher=resolved["token_hasher"],
        )

    def create_session_cookie(
        self,
        user_id: str,
        metadata: SessionMetadata | None = None,
    ) -> Cookie:
        session_token, _ = self.create_session(user_id, metadata)
        return make_session_cookie(session_token, self.session_config)

    def issue_token(self, request: TokenIssueRequest) -> tuple[str, int]:
        if self.token_issuer is not None:
            return self.token_issuer(request)

        if self.session_storage is None:
            raise CrossAuthException(
                "server_error",
                "The token endpoint requires token_issuer or session_storage",
            )

        resolved = resolve_config(self.session_config)
        session_token, _ = self.create_session(
            request.user_id,
            {
                "client_id": request.client_id,
                "user_agent": _get_header(request.http_request.headers, "user-agent"),
            },
        )
        return session_token, resolved["max_age"]

    def is_valid_redirect_uri(self, redirect_uri: str) -> bool:
        host = urlparse(redirect_uri).netloc

        for origin in self.trusted_origins:
            if is_same_host(host, origin):
                return True

        return False

    def is_valid_client_id(self, client_id: str) -> bool:
        """Validate client_id against allowed_client_ids config.

        If allowed_client_ids is not configured or empty, any client_id is accepted.
        """
        allowed = self.config.get("allowed_client_ids")

        if not allowed:
            return True

        return client_id in allowed
