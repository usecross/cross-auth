from collections.abc import Callable
from urllib.parse import urlparse

from cross_web import AsyncHTTPRequest, Cookie

from ._config import Config
from ._session import SessionConfig, create_session, make_session_cookie, resolve_config
from ._storage import AccountsStorage, SecondaryStorage, User
from .utils._is_same_host import is_same_host


class Context:
    def __init__(
        self,
        secondary_storage: SecondaryStorage,
        accounts_storage: AccountsStorage,
        create_token: Callable[[str], tuple[str, int]],
        # TODO: this doesn't allow to use the library as an Identity Provider
        trusted_origins: list[str],
        get_user_from_request: Callable[[AsyncHTTPRequest], User | None],
        base_url: str | None = None,
        config: Config | None = None,
        session_enabled: bool = False,
        session_config: SessionConfig | None = None,
        default_next_url: str = "/",
    ):
        self.secondary_storage = secondary_storage
        self.accounts_storage = accounts_storage
        self.create_token = create_token
        self.trusted_origins = trusted_origins
        self.get_user_from_request = get_user_from_request
        self.base_url = base_url
        self.config: Config = config if config is not None else {}
        self._session_enabled = session_enabled
        self.session_config = session_config
        self.default_next_url = default_next_url

    @property
    def is_session_enabled(self) -> bool:
        return self._session_enabled

    def create_session_cookie(self, user_id: str) -> Cookie:
        if not self.is_session_enabled:
            raise RuntimeError("Session flow not configured for this deployment")

        resolved = resolve_config(self.session_config)
        session_id, _ = create_session(
            user_id,
            self.secondary_storage,
            max_age=resolved["max_age"],
        )
        return make_session_cookie(session_id, self.session_config)

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
