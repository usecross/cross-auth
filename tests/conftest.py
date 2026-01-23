import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, cast

import pytest
from cross_web import AsyncHTTPRequest
from passlib.context import CryptContext

from cross_auth._context import Context
from cross_auth._issuer import AuthorizationCodeGrantData, Issuer
from cross_auth._storage import (
    AccountsStorage,
    SecondaryStorage,
    Session as SessionProtocol,
    User as UserProtocol,
)
from cross_auth.exceptions import CrossAuthException
from cross_auth.social_providers.oauth import OAuth2LinkCodeData

pytestmark = pytest.mark.asyncio

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Test password constant
TEST_PASSWORD = "password123"


@dataclass
class Session:
    """In-memory session for testing."""

    id: str
    user_id: str
    expires_at: datetime
    created_at: datetime
    ip_address: str | None = None
    user_agent: str | None = None


class MemorySessionStorage:
    """In-memory session storage for testing.

    Implements SessionStorage protocol via duck typing.
    """

    def __init__(self):
        self.sessions: dict[str, Session] = {}

    def create_session(
        self,
        user_id: Any,
        expires_at: datetime,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> SessionProtocol:
        session_id = str(uuid.uuid4())
        session = Session(
            id=session_id,
            user_id=str(user_id),
            expires_at=expires_at,
            created_at=datetime.now(tz=timezone.utc),
            ip_address=ip_address,
            user_agent=user_agent,
        )
        self.sessions[session_id] = session
        return session

    def get_session(self, session_id: str) -> SessionProtocol | None:
        session = self.sessions.get(session_id)
        if session and session.expires_at < datetime.now(tz=timezone.utc):
            # Session expired, clean up
            del self.sessions[session_id]
            return None
        return session

    def delete_session(self, session_id: str) -> None:
        self.sessions.pop(session_id, None)

    def delete_user_sessions(self, user_id: Any) -> None:
        user_id_str = str(user_id)
        to_delete = [
            sid for sid, s in self.sessions.items() if str(s.user_id) == user_id_str
        ]
        for sid in to_delete:
            del self.sessions[sid]

    def list_user_sessions(self, user_id: Any) -> list[SessionProtocol]:
        user_id_str = str(user_id)
        now = datetime.now(tz=timezone.utc)
        return [
            s
            for s in self.sessions.values()
            if str(s.user_id) == user_id_str and s.expires_at > now
        ]

    def update_session_expiry(self, session_id: str, expires_at: datetime) -> None:
        if session_id in self.sessions:
            self.sessions[session_id].expires_at = expires_at


@dataclass
class SocialAccount:
    id: str
    user_id: str
    provider_user_id: str
    provider: str
    access_token: str | None = None
    refresh_token: str | None = None
    access_token_expires_at: datetime | None = None
    refresh_token_expires_at: datetime | None = None
    scope: str | None = None
    provider_email: str | None = None
    provider_email_verified: bool | None = None
    is_login_method: bool = True


@dataclass
class User:
    id: str
    email: str
    email_verified: bool
    hashed_password: str
    social_accounts: list[SocialAccount]


class MemoryStorage(SecondaryStorage):
    def __init__(self):
        self.data = {}

    def set(self, key: str, value: str):
        self.data[key] = value

    def get(self, key: str) -> str | None:
        return self.data.get(key)

    def delete(self, key: str):
        del self.data[key]

    def pop(self, key: str) -> str | None:
        """Atomically get and delete a key. Returns None if key doesn't exist."""
        return self.data.pop(key, None)


class MemoryAccountsStorage:
    def __init__(self, test_password_hash: str):
        self.test_password_hash = test_password_hash
        self.data = {
            "test": User(
                id="test",
                email="test@example.com",
                email_verified=True,
                hashed_password=test_password_hash,
                social_accounts=[],
            )
        }

    def find_user_by_email(self, email: str) -> User | None:
        return next((user for user in self.data.values() if user.email == email), None)

    def find_user_by_id(self, id: Any) -> User | None:
        return self.data.get(id)

    def create_user(
        self,
        *,
        user_info: dict[str, Any],
        email: str,
        email_verified: bool,
    ) -> User:
        if self.find_user_by_email(email) is not None:
            raise ValueError("User already exists")

        if email == "not-allowed@example.com":
            raise CrossAuthException(
                "email_not_invited",
                "This email has not yet been invited to join FastAPI Cloud",
            )

        user = User(
            id=str(user_info["id"]),
            email=email,
            email_verified=email_verified,
            hashed_password=self.test_password_hash,
            social_accounts=[],
        )

        self.data[str(user_info["id"])] = user

        return user

    def create_user_with_password(
        self,
        *,
        email: str,
        hashed_password: str,
        email_verified: bool = False,
        user_info: dict[str, Any] | None = None,
    ) -> User:
        if self.find_user_by_email(email) is not None:
            raise ValueError("User already exists")

        if email == "not-allowed@example.com":
            raise CrossAuthException(
                "email_not_invited",
                "This email has not yet been invited to join FastAPI Cloud",
            )

        user_id = str(uuid.uuid4())
        user = User(
            id=user_id,
            email=email,
            email_verified=email_verified,
            hashed_password=hashed_password,
            social_accounts=[],
        )

        self.data[user_id] = user

        return user

    def find_social_account(
        self,
        provider: str,
        provider_user_id: str,
    ) -> SocialAccount | None:
        for user in self.data.values():
            for social_account in user.social_accounts:
                if (
                    social_account.provider == provider
                    and social_account.provider_user_id == provider_user_id
                ):
                    return social_account
        return None

    def create_social_account(
        self,
        *,
        user_id: str,
        provider: str,
        provider_user_id: str,
        access_token: str | None,
        refresh_token: str | None,
        access_token_expires_at: datetime | None,
        refresh_token_expires_at: datetime | None,
        scope: str | None,
        user_info: dict[str, Any],
        provider_email: str | None,
        provider_email_verified: bool | None,
        is_login_method: bool,
    ) -> SocialAccount:
        if user_id not in self.data:
            raise ValueError("User does not exist")

        user = self.data[user_id]

        social_account = SocialAccount(
            id=str(uuid.uuid4()),
            user_id=user_id,
            provider=provider,
            provider_user_id=provider_user_id,
            access_token=access_token,
            refresh_token=refresh_token,
            access_token_expires_at=access_token_expires_at,
            refresh_token_expires_at=refresh_token_expires_at,
            scope=scope,
            provider_email=provider_email,
            provider_email_verified=provider_email_verified,
            is_login_method=is_login_method,
        )

        user.social_accounts.append(social_account)

        self.data[user_id] = user

        return social_account

    def update_social_account(
        self,
        social_account_id: str,
        *,
        access_token: str | None,
        refresh_token: str | None,
        access_token_expires_at: datetime | None,
        refresh_token_expires_at: datetime | None,
        scope: str | None,
        user_info: dict[str, Any],
        provider_email: str | None,
        provider_email_verified: bool | None,
    ) -> SocialAccount:
        social_account = next(
            (
                social_account
                for user in self.data.values()
                for social_account in user.social_accounts
                if social_account.id == social_account_id
            ),
            None,
        )

        if social_account is None:
            raise ValueError("Social account does not exist")

        social_account.access_token = access_token
        social_account.refresh_token = refresh_token
        social_account.access_token_expires_at = access_token_expires_at
        social_account.refresh_token_expires_at = refresh_token_expires_at
        social_account.scope = scope
        social_account.provider_email = provider_email
        social_account.provider_email_verified = provider_email_verified

        return social_account


@pytest.fixture(scope="session")
def test_password_hash() -> str:
    return pwd_context.hash(TEST_PASSWORD)


@pytest.fixture
def secondary_storage() -> SecondaryStorage:
    return MemoryStorage()


@pytest.fixture
def accounts_storage(test_password_hash: str) -> MemoryAccountsStorage:
    return MemoryAccountsStorage(test_password_hash)


@pytest.fixture
def logged_in_user(accounts_storage: MemoryAccountsStorage) -> User:
    user = accounts_storage.find_user_by_email("test@example.com")
    assert user is not None
    return user


@pytest.fixture
def session_storage() -> MemorySessionStorage:
    return MemorySessionStorage()


@pytest.fixture
def context(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    logged_in_user: User,
) -> Context:
    def _get_user_from_request(request: AsyncHTTPRequest) -> UserProtocol | None:
        if request.headers.get("Authorization") == "Bearer test":
            return cast(UserProtocol, logged_in_user)

        return None

    return Context(
        secondary_storage=secondary_storage,
        accounts_storage=accounts_storage,
        create_token=lambda id: (f"token-{id}", 0),
        get_user_from_request=_get_user_from_request,
        trusted_origins=["valid-frontend.com"],
    )


@pytest.fixture
def context_with_sessions(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: MemorySessionStorage,
    logged_in_user: User,
) -> Context:
    def _get_user_from_request(request: AsyncHTTPRequest) -> UserProtocol | None:
        if request.headers.get("Authorization") == "Bearer test":
            return cast(UserProtocol, logged_in_user)

        return None

    return Context(
        secondary_storage=secondary_storage,
        accounts_storage=accounts_storage,
        create_token=lambda id: (f"token-{id}", 3600),
        get_user_from_request=_get_user_from_request,
        trusted_origins=["valid-frontend.com"],
        session_storage=session_storage,
        session_config={
            "cookie_name": "session_id",
            "expires_in": 7 * 24 * 60 * 60,  # 7 days
            "refresh_threshold": 24 * 60 * 60,  # 1 day
            "cookie_secure": False,  # Allow non-HTTPS in tests
            "cookie_httponly": True,
            "cookie_samesite": "lax",
            "cookie_path": "/",
        },
    )


@pytest.fixture
def issuer() -> Issuer:
    return Issuer()


@pytest.fixture
def expired_code(secondary_storage: SecondaryStorage) -> str:
    code = "test"
    secondary_storage.set(
        f"oauth:code:{code}",
        AuthorizationCodeGrantData(
            user_id="test",
            expires_at=datetime.now(tz=timezone.utc) - timedelta(seconds=1),
            client_id="test",
            redirect_uri="test",
            code_challenge="test",
            code_challenge_method="S256",
        ).model_dump_json(),
    )
    return code


@pytest.fixture
def valid_code(secondary_storage: SecondaryStorage) -> str:
    code = "test"
    # For code verifier "test", the S256 code challenge is "n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg"
    secondary_storage.set(
        f"oauth:code:{code}",
        AuthorizationCodeGrantData(
            user_id="test",
            expires_at=datetime.now(tz=timezone.utc) + timedelta(seconds=10),
            client_id="test",
            redirect_uri="test",
            code_challenge="n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
            code_challenge_method="S256",
        ).model_dump_json(),
    )
    return code


@pytest.fixture
def valid_link_code(secondary_storage: SecondaryStorage) -> str:
    code = "test"

    secondary_storage.set(
        f"oauth:link_request:{code}",
        OAuth2LinkCodeData(
            expires_at=datetime.now(tz=timezone.utc) + timedelta(seconds=10),
            client_id="test",
            redirect_uri="test",
            code_challenge="n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
            code_challenge_method="S256",
            user_id="test",
            provider_code="1234567890",
        ).model_dump_json(),
    )

    return code
