import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, cast

import pytest
from cross_web import HTTPRequest
from passlib.context import CryptContext

from cross_auth._auth_flow import LinkCodeData
from cross_auth._context import Context
from cross_auth._issuer import AuthorizationCodeGrantData, Issuer
from cross_auth._storage import (
    AccountsStorage,
    SecondaryStorage,
    SessionListOrder,
    SessionListResult,
    SessionStatus,
    SessionStorage,
    User as UserProtocol,
    session_status,
)
from cross_auth.exceptions import CrossAuthException

pytestmark = pytest.mark.asyncio

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Test password constant
TEST_PASSWORD = "password123"


def _same_id(left: Any, right: Any) -> bool:
    return str(left) == str(right)


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
    hashed_password: str | None
    social_accounts: list[SocialAccount]

    @property
    def has_usable_password(self) -> bool:
        return self.hashed_password is not None


class MemoryStorage(SecondaryStorage):
    def __init__(self) -> None:
        self.data: dict[str, tuple[str, float | None]] = {}

    def set(self, key: str, value: str, ttl: int | None = None) -> None:
        expires_at = time.monotonic() + ttl if ttl is not None else None
        self.data[key] = (value, expires_at)

    def get(self, key: str) -> str | None:
        if (entry := self.data.get(key)) is None:
            return None
        value, expires_at = entry
        if expires_at is not None and time.monotonic() >= expires_at:
            del self.data[key]
            return None
        return value

    def delete(self, key: str) -> None:
        self.data.pop(key, None)

    def pop(self, key: str) -> str | None:
        """Atomically get and delete a key. Returns None if key doesn't exist."""
        value = self.get(key)
        self.data.pop(key, None)
        return value


@dataclass
class MemorySessionRecord:
    id: str
    token_hash: str
    user_id: str
    created_at: datetime
    updated_at: datetime
    expires_at: datetime
    last_active_at: datetime | None = None
    revoked_at: datetime | None = None
    client_id: str | None = None
    client_name: str | None = None
    user_agent: str | None = None
    ip: str | None = None

    @property
    def status(self) -> SessionStatus:
        return session_status(self)


@dataclass
class MemorySessionListResult:
    records: list[MemorySessionRecord]
    next_cursor: str | None = None


class MemorySessionStorage(SessionStorage):
    def __init__(self):
        self.records: dict[str, MemorySessionRecord] = {}

    def create(
        self,
        *,
        token_hash: str,
        user_id: Any,
        created_at: datetime,
        updated_at: datetime,
        expires_at: datetime,
        client_id: str | None = None,
        client_name: str | None = None,
        user_agent: str | None = None,
        ip: str | None = None,
        last_active_at: datetime | None = None,
    ) -> MemorySessionRecord:
        record = MemorySessionRecord(
            id=str(uuid.uuid4()),
            token_hash=token_hash,
            user_id=str(user_id),
            created_at=created_at,
            updated_at=updated_at,
            expires_at=expires_at,
            client_id=client_id,
            client_name=client_name,
            user_agent=user_agent,
            ip=ip,
            last_active_at=last_active_at,
        )
        self.records[record.id] = record
        return record

    def get(self, *, token_hash: str, now: datetime) -> MemorySessionRecord | None:
        record = next(
            (
                record
                for record in self.records.values()
                if record.token_hash == token_hash
            ),
            None,
        )
        if record is None or session_status(record, now=now) != "active":
            return None
        return record

    def get_any(self, session_id: Any) -> MemorySessionRecord | None:
        return self.records.get(str(session_id))

    def list_for_user(
        self,
        user_id: Any,
        *,
        now: datetime,
        status: SessionStatus | None = None,
        order_by: SessionListOrder = "updated_at_desc",
        limit: int = 50,
        cursor: str | None = None,
    ) -> SessionListResult:
        records = [
            record for record in self.records.values() if record.user_id == str(user_id)
        ]
        if status is not None:
            records = [
                record
                for record in records
                if session_status(record, now=now) == status
            ]

        field, direction = order_by.rsplit("_", 1)
        records.sort(
            key=lambda record: getattr(record, field),
            reverse=direction == "desc",
        )
        return cast(
            SessionListResult,
            MemorySessionListResult(records=records[:limit]),
        )

    def refresh(
        self,
        session_id: Any,
        *,
        updated_at: datetime,
        expires_at: datetime,
        last_active_at: datetime | None = None,
    ) -> MemorySessionRecord | None:
        record = self.get_any(session_id)
        if record is None:
            return None
        record.updated_at = updated_at
        record.expires_at = expires_at
        if last_active_at is not None:
            record.last_active_at = last_active_at
        return record

    def revoke(self, session_id: Any, *, revoked_at: datetime) -> None:
        record = self.get_any(session_id)
        if record is not None and record.revoked_at is None:
            record.revoked_at = revoked_at

    def revoke_all_for_user(
        self,
        user_id: Any,
        *,
        revoked_at: datetime,
        except_session_id: Any | None = None,
    ) -> int:
        count = 0
        for record in self.records.values():
            if record.user_id != str(user_id):
                continue
            if except_session_id is not None and record.id == str(except_session_id):
                continue
            if record.revoked_at is None:
                record.revoked_at = revoked_at
                count += 1
        return count


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

    def find_social_account_by_id(
        self,
        social_account_id: Any,
    ) -> SocialAccount | None:
        return next(
            (
                social_account
                for user in self.data.values()
                for social_account in user.social_accounts
                if _same_id(social_account.id, social_account_id)
            ),
            None,
        )

    def list_social_accounts(self, *, user_id: Any) -> list[SocialAccount]:
        user = self.find_user_by_id(user_id)
        if user is None:
            return []
        return list(user.social_accounts)

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
                if _same_id(social_account.id, social_account_id)
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

    def delete_social_account(self, social_account_id: Any) -> None:
        for user in self.data.values():
            user.social_accounts = [
                account
                for account in user.social_accounts
                if not _same_id(account.id, social_account_id)
            ]


@pytest.fixture(scope="session")
def test_password_hash() -> str:
    return pwd_context.hash(TEST_PASSWORD)


@pytest.fixture
def secondary_storage() -> SecondaryStorage:
    return MemoryStorage()


@pytest.fixture
def session_storage() -> MemorySessionStorage:
    return MemorySessionStorage()


@pytest.fixture
def accounts_storage(test_password_hash: str) -> MemoryAccountsStorage:
    return MemoryAccountsStorage(test_password_hash)


@pytest.fixture
def logged_in_user(accounts_storage: MemoryAccountsStorage) -> User:
    user = accounts_storage.find_user_by_email("test@example.com")
    assert user is not None
    return user


@pytest.fixture
def context(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
    logged_in_user: User,
) -> Context:
    def _get_user_from_request(request: HTTPRequest) -> UserProtocol | None:
        if request.headers.get("Authorization") == "Bearer test":
            return cast(UserProtocol, logged_in_user)

        return None

    return Context(
        secondary_storage=secondary_storage,
        accounts_storage=accounts_storage,
        session_storage=session_storage,
        get_user_from_request=_get_user_from_request,
        trusted_origins=["valid-frontend.com"],
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
        LinkCodeData(
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
