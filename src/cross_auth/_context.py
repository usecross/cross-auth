from collections.abc import Callable

from cross_web import HTTPRequest, Cookie

from ._clients import ClientResolver, OAuthClient
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


class Context:
    def __init__(
        self,
        secondary_storage: SecondaryStorage,
        accounts_storage: AccountsStorage,
        trusted_origins: list[str],
        get_user_from_request: Callable[[HTTPRequest], User | None],
        session_storage: SessionStorage | None = None,
        token_issuer: TokenIssuer | None = None,
        base_url: str | None = None,
        config: Config | None = None,
        default_next_url: str = "/",
        hooks: HookRegistry | None = None,
        normalize_email: Callable[[str], str] | None = None,
        get_client: ClientResolver | None = None,
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
        if "allowed_client_ids" in self.config:
            raise ValueError(
                "Replace allowed_client_ids with client_redirect_uris or get_client: "
                "register exact callback URLs for each client"
            )

        if get_client is not None and self.config.get("client_redirect_uris"):
            raise ValueError("Use get_client or client_redirect_uris, not both")

        self._get_client = get_client
        for client_id, redirect_uris in self.config.get(
            "client_redirect_uris", {}
        ).items():
            OAuthClient(client_id=client_id, redirect_uris=tuple(redirect_uris))

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

    def get_client(self, client_id: str) -> OAuthClient | None:
        """Look up the current registration without caching application results."""
        if self._get_client is not None:
            client = self._get_client(client_id)
        else:
            redirects = self.config.get("client_redirect_uris", {}).get(client_id)
            client = (
                OAuthClient(client_id=client_id, redirect_uris=tuple(redirects))
                if redirects
                else None
            )

        if client is not None and client.client_id != client_id:
            raise ValueError("get_client returned a different client_id")

        return client

    def is_valid_redirect_uri(self, redirect_uri: str, *, client_id: str) -> bool:
        client = self.get_client(client_id)
        return client is not None and client.check_redirect_uri(redirect_uri)
