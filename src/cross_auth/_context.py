from collections.abc import Callable
from dataclasses import replace
from typing import TypeVar

from cross_web import HTTPRequest

from ._clients import OAuthClient
from ._config import Config
from ._email import normalize_email as _default_normalize_email
from ._login import issue_bearer_session, run_login, run_now
from ._oauth_server import OAuthServer
from ._session import (
    AuthenticatedSession,
    ResolvedSession,
    SessionConfig,
    SessionMetadata,
    UserCanAuthenticate,
    authenticate_session_token,
    create_session,
    get_session,
    request_metadata,
    resolve_config,
    resolve_current_session,
    validate_activity_interval,
)
from ._storage import (
    AccountsStorage,
    SecondaryStorage,
    SessionRecord,
    SessionStorage,
    User,
)
from ._token_format import is_well_formed, validate_prefix
from ._tokens import IssuedToken, TokenIssueRequest, TokenKind
from .exceptions import CrossAuthException
from .hooks import BeforeLoginEvent, HookRegistry

StorageT = TypeVar("StorageT")


def _sign_in_refused() -> CrossAuthException:
    """The error for a user ``user_can_authenticate`` returned False for."""
    return CrossAuthException(
        "access_denied", error_description="Sign-in is not allowed", status_code=403
    )


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
        user_can_authenticate: UserCanAuthenticate | None = None,
    ):
        self.secondary_storage = secondary_storage
        self.accounts_storage = accounts_storage
        self.session_storage = session_storage
        self.get_user_from_request = get_user_from_request
        # None lets every user sign in without loading them to ask.
        self.user_can_authenticate = user_can_authenticate
        if oauth_server is not None and not isinstance(oauth_server, OAuthServer):
            raise TypeError("oauth_server must be an OAuthServer or None")
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
        token_prefix = (self.session_config or {}).get("token_prefix")
        if token_prefix is not None:
            validate_prefix(token_prefix)
        validate_activity_interval(
            resolve_config(self.session_config)["activity_interval"]
        )
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

    def check_user_can_authenticate(self, user: User) -> None:
        """Raise ``CrossAuthException`` unless ``user`` may sign in.

        ``user_can_authenticate`` returning False raises ``access_denied``; an
        exception it raises propagates. Call it only once the user's identity
        is verified, so nobody learns an account's state without credentials.
        """
        user_can_authenticate = self.user_can_authenticate
        if user_can_authenticate is not None and not user_can_authenticate(user):
            raise _sign_in_refused()

    def check_user_id_can_authenticate(self, user_id: str) -> None:
        """``check_user_can_authenticate`` for the user with ``user_id``.

        A user that is not found is refused. Without ``user_can_authenticate``
        nothing is loaded.
        """
        if self.user_can_authenticate is None:
            return
        user = self.accounts_storage.find_user_by_id(user_id)
        if user is None:
            raise _sign_in_refused()
        self.check_user_can_authenticate(user)

    def resolve_current_session(
        self, request: HTTPRequest, *, load_user: bool = False
    ) -> ResolvedSession | None:
        """Resolve the request's session, cookie first, then bearer token.

        With ``load_user``, or with ``user_can_authenticate``, the session's
        user is loaded before any sliding refresh: a session whose user is not
        found or refused counts as unknown and is not extended. A
        ``CrossAuthException`` from ``user_can_authenticate`` propagates.
        """
        session_storage = self.session_storage
        if session_storage is None:
            raise RuntimeError("Session flow not configured for this deployment")

        check = load_user or self.user_can_authenticate is not None
        return resolve_current_session(
            request,
            session_storage,
            self.session_config,
            accounts_storage=self.accounts_storage if check else None,
            user_can_authenticate=self.user_can_authenticate,
        )

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
            token_prefix=resolved["token_prefix"],
            login_method=login_method,
            store_ip=resolved["store_ip"],
        )

    def identify_token(self, token: str) -> TokenKind | None:
        """Name the kind of Cross-Auth token ``token`` looks like, or ``None``.

        Returns ``"session"`` when the session ``token_prefix`` is configured
        and ``token`` has that prefix and a valid checksum. This only reads
        the token's shape and does not authenticate it: a well-formed token
        can be unknown, expired or revoked, and sessions issued before the
        prefix was set are not recognized. Use it to route a credential or to
        reject a malformed one before a storage lookup.
        """
        token_prefix = (self.session_config or {}).get("token_prefix")
        if token_prefix is not None and is_well_formed(token, token_prefix):
            return "session"
        return None

    def authenticate_session_token(
        self, token: str, *, db_session: object | None = None
    ) -> AuthenticatedSession | None:
        """Return the active session ``token`` belongs to and its user.

        Returns ``None`` when the token is unknown, revoked or expired, when
        the accounts storage does not return its user, or when
        ``user_can_authenticate`` returns False for it; an exception it raises
        propagates. Sliding sessions are refreshed as they are for requests,
        once the user is checked.

        Pass ``db_session`` to load the user in your own database session, so
        the returned user belongs to it. The accounts storage must have a
        ``with_read_session`` method, as the SQLModel one does. The session
        lookup, the ``user_can_authenticate`` check and any refresh run first,
        in the storages' own sessions, so a refresh never commits while this
        call has a transaction open in ``db_session``.
        """
        session_storage = self.session_storage
        if session_storage is None:
            raise RuntimeError("Session flow not configured for this deployment")

        if db_session is None:
            return authenticate_session_token(
                token,
                session_storage,
                self.accounts_storage,
                self.session_config,
                user_can_authenticate=self.user_can_authenticate,
            )

        reader = _with_read_session(self.accounts_storage, db_session)
        if self.user_can_authenticate is None:
            session = get_session(token, session_storage, self.session_config)
        else:
            # The check needs the user before the refresh, and the refresh
            # must not commit after a read in db_session, so check a copy
            # loaded in the accounts storage's own session.
            checked = authenticate_session_token(
                token,
                session_storage,
                self.accounts_storage,
                self.session_config,
                user_can_authenticate=self.user_can_authenticate,
            )
            session = None if checked is None else checked.session
        if session is None:
            return None
        user = reader.find_user_by_id(session.user_id)
        if user is None:
            return None
        return AuthenticatedSession(session, user)

    def issue_token(self, request: TokenIssueRequest) -> tuple[str, int]:
        """Log ``request.user_id`` in with a bearer token for the token endpoint.

        Runs the ``login`` hooks around the OAuth server's ``token_issuer``
        call or, without one, around a new session.
        """
        issued = self.issue_token_result(request)
        return issued.token, issued.expires_in

    def issue_token_result(self, request: TokenIssueRequest) -> IssuedToken:
        """Issue a bearer credential together with its actual commit scheduler."""
        token_issuer = (
            None if self.oauth_server is None else self.oauth_server.token_issuer
        )
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
                issue=lambda event: (
                    token_issuer(replace(request, login_method=event.login_method)),
                    None,
                ),
                # A token_issuer's successful return is its commit point; core
                # cannot see any transaction behind it.
                on_commit=run_now,
                check_user=self.check_user_id_can_authenticate,
            )
            return IssuedToken(*issued, on_commit=run_now)

        session_storage = self.session_storage
        if session_storage is None:
            raise CrossAuthException(
                "server_error",
                "The token endpoint requires token_issuer or session_storage",
            )

        session_token, _, expires_in = issue_bearer_session(
            request.user_id,
            hooks=self.hooks,
            session_storage=session_storage,
            session_config=self.session_config,
            check_user=self.check_user_id_can_authenticate,
            metadata={
                "client_id": request.client_id,
                **request_metadata(request.http_request, self.session_config),
            },
            login_method=request.login_method,
        )
        return IssuedToken(
            session_token, expires_in, on_commit=session_storage.on_commit
        )

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


def _with_read_session(storage: StorageT, db_session: object) -> StorageT:
    with_read_session = getattr(storage, "with_read_session", None)
    if with_read_session is None:
        raise TypeError(
            f"{type(storage).__name__} cannot read in a caller's database session: "
            "it has no with_read_session method"
        )
    return with_read_session(db_session)
