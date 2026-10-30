from collections.abc import Callable
from dataclasses import replace

from cross_web import HTTPRequest

from ._clients import OAuthClient
from ._config import Config
from ._email import normalize_email as _default_normalize_email
from ._login import issue_bearer_session, run_login, run_now
from ._oauth_server import OAuthServer
from ._session import (
    SessionConfig,
    SessionMetadata,
    _get_header,
    create_session,
    resolve_config,
)
from ._storage import (
    AccountsStorage,
    CommitCallback,
    SecondaryStorage,
    SessionRecord,
    SessionStorage,
    User,
)
from ._tokens import TokenIssueRequest, TokenIssuer
from .exceptions import CrossAuthException
from .hooks import BeforeLoginEvent, HookRegistry


class Context:
    def __init__(
        self,
        secondary_storage: SecondaryStorage,
        accounts_storage: AccountsStorage,
        get_user_from_request: Callable[[HTTPRequest], User | None],
        session_storage: SessionStorage | None = None,
        *,
        base_url: str | None = None,
        config: Config | None = None,
        default_next_url: str = "/",
        hooks: HookRegistry | None = None,
        normalize_email: Callable[[str], str] | None = None,
        oauth_server: OAuthServer | None = None,
    ):
        self.secondary_storage = secondary_storage
        self.accounts_storage = accounts_storage
        self.session_storage = session_storage
        self.get_user_from_request = get_user_from_request
        if oauth_server is not None and not isinstance(oauth_server, OAuthServer):
            raise TypeError("oauth_server must be an OAuthServer or None")
        # Mounts /authorize, /token, /link and /finalize-link; None leaves them out.
        self.oauth_server = oauth_server
        self.base_url = base_url
        # Applied to every user lookup/creation by email (not to the raw
        # provider_email stored on social accounts).
        self.normalize_email = (
            normalize_email if normalize_email is not None else _default_normalize_email
        )
        self.config: Config = config if config is not None else {}
        unknown = self.config.keys() - Config.__optional_keys__
        if unknown:
            raise ValueError(f"Unknown config keys: {', '.join(sorted(unknown))}")

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
        *,
        login_method: str | None = None,
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
            login_method=login_method,
        )

    def issue_token(self, request: TokenIssueRequest) -> tuple[str, int]:
        """Log ``request.user_id`` in with a bearer token for the token endpoint.

        Runs the ``login`` hooks around the OAuth server's ``token_issuer``
        call or, without one, around a new session.
        """
        token_issuer = self._token_issuer
        if token_issuer is not None:
            issued, _ = run_login(
                BeforeLoginEvent(
                    user_id=request.user_id,
                    credential="bearer",
                    max_age=None,
                    metadata=None,
                    login_method=request.login_method,
                ),
                hooks=self.hooks,
                # The issuer sees the login_method the before hooks approved.
                issue=lambda event: (
                    token_issuer(replace(request, login_method=event.login_method)),
                    None,
                ),
                # A token_issuer's successful return is its commit point; core
                # cannot see any transaction behind it.
                on_commit=run_now,
            )
            return issued

        if self.session_storage is None:
            raise CrossAuthException(
                "server_error",
                "The token endpoint requires token_issuer or session_storage",
            )

        session_token, _, expires_in = issue_bearer_session(
            request.user_id,
            hooks=self.hooks,
            session_storage=self.session_storage,
            session_config=self.session_config,
            metadata={
                "client_id": request.client_id,
                "user_agent": _get_header(request.http_request.headers, "user-agent"),
            },
            login_method=request.login_method,
        )
        return session_token, expires_in

    @property
    def _token_issuer(self) -> TokenIssuer | None:
        return None if self.oauth_server is None else self.oauth_server.token_issuer

    def _on_token_commit(self, callback: CommitCallback) -> None:
        """Schedule callback after the credential ``issue_token`` stored commits."""
        if self._token_issuer is None and self.session_storage is not None:
            self.session_storage.on_commit(callback)
        else:
            callback()

    def get_client(self, client_id: str) -> OAuthClient | None:
        """Look up the current registration without caching application results."""
        if self.oauth_server is None or self.oauth_server.get_client is None:
            return None

        client = self.oauth_server.get_client(client_id)
        if client is not None and client.client_id != client_id:
            raise ValueError("get_client returned a different client_id")

        return client

    def is_valid_redirect_uri(self, redirect_uri: str, *, client_id: str) -> bool:
        client = self.get_client(client_id)
        return client is not None and client.check_redirect_uri(redirect_uri)
