---
title: Storage
description:
  Implement the storage protocols to connect Cross-Auth to your database.
order: 1
section: Guides
---

## Overview

Cross-Auth uses Python protocol classes (structural subtyping) for storage. You
don't need to inherit from a base class -- just implement the required methods
and Cross-Auth will accept your objects.

Cross-Auth separates transient OAuth state from durable session state:

- `SecondaryStorage` stores short-lived values such as authorization codes, PKCE
  challenges, and link codes.
- `SessionStorage` stores revocable session records for browser cookies and
  bearer tokens issued by `/token`.

## AccountsStorage

The `AccountsStorage` protocol defines how Cross-Auth looks up and creates
users.

```python
class AccountsStorage(Protocol):
    def find_user_by_email(self, email: str) -> User | None: ...
    def find_user_by_id(self, id: Any) -> User | None: ...
    def find_social_account(
        self, *, provider: str, provider_user_id: str
    ) -> SocialAccount | None: ...
    def find_social_account_by_id(
        self, social_account_id: Any
    ) -> SocialAccount | None: ...
    def list_social_accounts(self, *, user_id: Any) -> Iterable[SocialAccount]: ...
    def create_user(
        self, *, user_info: dict[str, Any], email: str, email_verified: bool
    ) -> User: ...
    def create_social_account(self, **kwargs) -> SocialAccount: ...
    def update_social_account(self, social_account_id, **kwargs) -> SocialAccount: ...
    def delete_social_account(self, social_account_id: Any) -> None: ...
```

### User Protocol

Your user model must expose these attributes:

```python
class User(Protocol):
    id: Any
    email: str
    email_verified: bool
    hashed_password: str | None

    @property
    def has_usable_password(self) -> bool: ...

    @property
    def social_accounts(self) -> Iterable[SocialAccount]: ...
```

## SecondaryStorage

The `SecondaryStorage` protocol is used for ephemeral OAuth data: authorization
codes, PKCE challenges, and link codes.

```python
class SecondaryStorage(Protocol):
    def set(self, key: str, value: str, ttl: int | None = None): ...
    def get(self, key: str) -> str | None: ...
    def delete(self, key: str): ...
    def pop(self, key: str) -> str | None: ...
```

A Redis-backed implementation is a good fit for production:

```python
import redis


class RedisStorage:
    def __init__(self, url: str = "redis://localhost:6379"):
        self.client = redis.from_url(url)

    def set(self, key: str, value: str, ttl: int | None = None):
        self.client.set(key, value, ex=ttl)

    def get(self, key: str) -> str | None:
        result = self.client.get(key)
        return result.decode() if result else None

    def delete(self, key: str):
        self.client.delete(key)

    def pop(self, key: str) -> str | None:
        pipe = self.client.pipeline()
        pipe.get(key)
        pipe.delete(key)
        result, _ = pipe.execute()
        return result.decode() if result else None
```

## SessionStorage

The `SessionStorage` protocol stores durable, revocable session records. Browser
session cookies and OAuth bearer tokens both contain opaque session tokens; only
the token hash is stored.

```python
class SessionRecord(Protocol):
    id: Any
    user_id: Any
    created_at: AwareDatetime
    updated_at: AwareDatetime
    expires_at: AwareDatetime
    last_active_at: AwareDatetime | None
    revoked_at: AwareDatetime | None
    client_id: str | None
    client_name: str | None
    user_agent: str | None
    ip: str | None

    @property
    def status(self) -> Literal["active", "expired", "revoked"]: ...


class SessionListResult(Protocol):
    records: Sequence[SessionRecord]
    next_cursor: str | None


class SessionStorage(Protocol):
    def create(
        self,
        *,
        token_hash: str,
        user_id: Any,
        created_at: AwareDatetime,
        updated_at: AwareDatetime,
        expires_at: AwareDatetime,
        client_id: str | None = None,
        client_name: str | None = None,
        user_agent: str | None = None,
        ip: str | None = None,
        last_active_at: AwareDatetime | None = None,
    ) -> SessionRecord: ...

    def get(self, *, token_hash: str, now: AwareDatetime) -> SessionRecord | None: ...
    def get_any(self, session_id: Any) -> SessionRecord | None: ...
    def refresh(self, session_id: Any, **kwargs) -> SessionRecord | None: ...
    def revoke(self, session_id: Any, *, revoked_at: AwareDatetime) -> None: ...
    def list_for_user(self, user_id: Any, **kwargs) -> SessionListResult: ...
    def revoke_all_for_user(self, user_id: Any, **kwargs) -> int: ...
```

`session_storage` is optional when constructing `CrossAuth`, but session-backed
features require it. `login()`, `logout()`, and session-management methods raise
clearly when no `session_storage` is configured. The built-in `/token` endpoint
is still registered, but successful token issuance requires `session_storage`.
