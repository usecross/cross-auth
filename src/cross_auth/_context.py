from collections.abc import Callable
from datetime import datetime, timezone
from urllib.parse import urlparse

from cross_web import AsyncHTTPRequest, Cookie

from ._config import Config, SessionConfig
from ._storage import AccountsStorage, SecondaryStorage, Session, SessionStorage, User
from .utils._is_same_host import is_same_host

# Default session configuration values
DEFAULT_SESSION_CONFIG: SessionConfig = {
    "cookie_name": "session_id",
    "expires_in": 7 * 24 * 60 * 60,  # 7 days
    "refresh_threshold": 24 * 60 * 60,  # 1 day
    "cookie_secure": True,
    "cookie_httponly": True,
    "cookie_samesite": "lax",
    "cookie_path": "/",
    "cookie_domain": None,
}


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
        # Session-based auth (optional)
        session_storage: SessionStorage | None = None,
        session_config: SessionConfig | None = None,
    ):
        self.secondary_storage = secondary_storage
        self.accounts_storage = accounts_storage
        self.create_token = create_token
        self.trusted_origins = trusted_origins
        self.get_user_from_request = get_user_from_request
        self.base_url = base_url
        self.config: Config = config or {}

        # Session support
        self.session_storage = session_storage
        self._session_config: SessionConfig = {
            **DEFAULT_SESSION_CONFIG,
            **(session_config or {}),
        }

    @property
    def session_enabled(self) -> bool:
        """Check if session-based authentication is enabled."""
        return self.session_storage is not None

    def get_session_config(self, key: str) -> str | int | bool | None:
        """Get a session configuration value with defaults."""
        return self._session_config.get(key, DEFAULT_SESSION_CONFIG.get(key))

    def get_session_from_request(self, request: AsyncHTTPRequest) -> Session | None:
        """Extract and validate session from request cookie.

        Returns the session if valid and not expired, None otherwise.
        Also handles session refresh if close to expiry.
        """
        if not self.session_storage:
            return None

        cookie_name = str(self.get_session_config("cookie_name"))
        session_id = request.cookies.get(cookie_name)

        if not session_id:
            return None

        session = self.session_storage.get_session(session_id)

        if not session:
            return None

        # Check if session is expired
        if session.expires_at < datetime.now(tz=timezone.utc):
            self.session_storage.delete_session(session_id)
            return None

        return session

    def should_refresh_session(self, session: Session) -> bool:
        """Check if session should be refreshed (sliding sessions)."""
        refresh_threshold = int(self.get_session_config("refresh_threshold") or 0)

        if refresh_threshold <= 0:
            return False

        time_until_expiry = (
            session.expires_at - datetime.now(tz=timezone.utc)
        ).total_seconds()
        return time_until_expiry < refresh_threshold

    def create_session_cookie(
        self, session: Session, expires_at: datetime | None = None
    ) -> Cookie:
        """Create a cookie for the given session."""
        cookie_name = str(self.get_session_config("cookie_name"))
        cookie_secure = bool(self.get_session_config("cookie_secure"))
        cookie_httponly = bool(self.get_session_config("cookie_httponly"))
        cookie_samesite = str(self.get_session_config("cookie_samesite"))
        cookie_path = str(self.get_session_config("cookie_path"))
        cookie_domain = self.get_session_config("cookie_domain")

        # Use session expiry or provided expiry
        expiry = expires_at or session.expires_at
        # Convert expiry to max_age in seconds
        max_age = int((expiry - datetime.now(tz=timezone.utc)).total_seconds())

        return Cookie(
            name=cookie_name,
            value=session.id,
            max_age=max_age,
            path=cookie_path,
            domain=str(cookie_domain) if cookie_domain else None,
            secure=cookie_secure,
            httponly=cookie_httponly,
            samesite=cookie_samesite,  # type: ignore
        )

    def create_logout_cookie(self) -> Cookie:
        """Create a cookie that clears the session."""
        cookie_name = str(self.get_session_config("cookie_name"))
        cookie_path = str(self.get_session_config("cookie_path"))
        cookie_domain = self.get_session_config("cookie_domain")
        cookie_secure = bool(self.get_session_config("cookie_secure"))

        # Set max_age=0 to delete the cookie
        return Cookie(
            name=cookie_name,
            value="",
            max_age=0,
            path=cookie_path,
            domain=str(cookie_domain) if cookie_domain else None,
            secure=cookie_secure,
        )

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
