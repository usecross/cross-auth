---
title: Storage Implementation
description: Learn about implementing storage for Cross Auth
section: Core Concepts
order: 2
---

# Storage Implementation

Cross Auth requires two storage implementations: one for temporary data and one for persistent data.

## Secondary Storage

Used for temporary data like OAuth state, authorization codes, and link codes. Typically implemented with Redis or similar cache.

```python
from cross_auth._storage import SecondaryStorage

class RedisSecondaryStorage(SecondaryStorage):
    def __init__(self, redis_client):
        self.redis = redis_client

    def set(self, key: str, value: str):
        # Set with TTL (e.g., 10 minutes)
        self.redis.setex(key, 600, value)

    def get(self, key: str) -> str | None:
        value = self.redis.get(key)
        return value.decode() if value else None

    def delete(self, key: str):
        self.redis.delete(key)

    def pop(self, key: str) -> str | None:
        # Atomically get and delete
        value = self.get(key)
        if value:
            self.delete(key)
        return value
```

## Accounts Storage

Used for persistent user and social account data. Implement with your database ORM (SQLAlchemy, Django ORM, etc.).

```python
from cross_auth._storage import AccountsStorage, User, SocialAccount
from datetime import datetime
from typing import Any

class DatabaseAccountsStorage(AccountsStorage):
    def find_user_by_email(self, email: str) -> User | None:
        # Query your database
        return db.query(UserModel).filter_by(email=email).first()

    def find_user_by_id(self, id: Any) -> User | None:
        return db.query(UserModel).filter_by(id=id).first()

    def find_social_account(
        self,
        *,
        provider: str,
        provider_user_id: str,
    ) -> SocialAccount | None:
        return db.query(SocialAccountModel).filter_by(
            provider=provider,
            provider_user_id=provider_user_id
        ).first()

    def create_user(self, *, user_info: dict[str, Any]) -> User:
        user = UserModel(
            email=user_info["email"],
            # ... other fields
        )
        db.add(user)
        db.commit()
        return user

    def create_social_account(
        self,
        *,
        user_id: Any,
        provider: str,
        provider_user_id: str,
        access_token: str | None,
        refresh_token: str | None,
        access_token_expires_at: datetime | None,
        refresh_token_expires_at: datetime | None,
        scope: str | None,
        user_info: dict[str, Any],
    ) -> SocialAccount:
        account = SocialAccountModel(
            user_id=user_id,
            provider=provider,
            provider_user_id=provider_user_id,
            access_token=access_token,
            # ... other fields
        )
        db.add(account)
        db.commit()
        return account

    def update_social_account(
        self,
        social_account_id: Any,
        *,
        access_token: str | None,
        refresh_token: str | None,
        access_token_expires_at: datetime | None,
        refresh_token_expires_at: datetime | None,
        scope: str | None,
        user_info: dict[str, Any],
    ) -> SocialAccount:
        account = db.query(SocialAccountModel).get(social_account_id)
        account.access_token = access_token
        # ... update other fields
        db.commit()
        return account
```

## User and SocialAccount Protocols

Your models must satisfy these protocols:

```python
# User Protocol
class User(Protocol):
    id: Any
    email: str
    hashed_password: str | None

    @property
    def social_accounts(self) -> Iterable[SocialAccount]: ...

# SocialAccount Protocol
class SocialAccount(Protocol):
    id: Any
    user_id: Any
    provider_user_id: str
    provider: str
```
