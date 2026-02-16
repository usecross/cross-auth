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
    def create_user(
        self, *, user_info: dict[str, Any], email: str, email_verified: bool
    ) -> User: ...
    def create_social_account(self, **kwargs) -> SocialAccount: ...
    def update_social_account(self, social_account_id, **kwargs) -> SocialAccount: ...
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
    def social_accounts(self) -> Iterable[SocialAccount]: ...
```

## SecondaryStorage

The `SecondaryStorage` protocol is used for ephemeral data: sessions, OAuth
authorization codes, and PKCE challenges.

```python
class SecondaryStorage(Protocol):
    def set(self, key: str, value: str): ...
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

    def set(self, key: str, value: str):
        self.client.set(key, value)

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
