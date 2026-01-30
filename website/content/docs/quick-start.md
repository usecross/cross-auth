---
title: Quick Start
description: Get up and running with Cross-Auth session authentication in minutes.
order: 3
section: Getting Started
---

## Overview

This guide walks you through adding email/password login to a FastAPI application using Cross-Auth's session functions. The same functions work with any Python web framework.

## Step 1: Implement Storage

Cross-Auth uses protocol classes to abstract storage. You need two implementations:

- **`AccountsStorage`** -- For looking up users by email or ID.
- **`SecondaryStorage`** -- For storing sessions (Redis, in-memory dict, database, etc.).

```python
from cross_auth._storage import AccountsStorage, SecondaryStorage

# Example: in-memory secondary storage (use Redis in production)
class MemoryStorage:
    def __init__(self):
        self.data = {}

    def set(self, key: str, value: str):
        self.data[key] = value

    def get(self, key: str) -> str | None:
        return self.data.get(key)

    def delete(self, key: str):
        self.data.pop(key, None)

    def pop(self, key: str) -> str | None:
        return self.data.pop(key, None)
```

## Step 2: Authenticate and Create a Session

```python
from cross_auth import authenticate, create_session, make_session_cookie

def login(email: str, password: str):
    user = authenticate(email, password, accounts_storage)
    if user is None:
        return None  # Invalid credentials

    session_id, session_data = create_session(str(user.id), session_storage)
    cookie = make_session_cookie(session_id)
    return cookie
```

## Step 3: Read the Session

```python
from cross_auth import get_session

def get_current_user(session_id: str):
    session = get_session(session_id, session_storage)
    if session is None:
        return None  # No valid session

    return accounts_storage.find_user_by_id(session.user_id)
```

## Step 4: Logout

```python
from cross_auth import delete_session, make_clear_cookie

def logout(session_id: str):
    delete_session(session_id, session_storage)
    return make_clear_cookie()
```

## Next Steps

- [Session Authentication](/docs/session-authentication) -- Full guide on session management.
- [Storage](/docs/storage) -- How to implement the storage protocols.
- [OAuth 2.0](/docs/oauth) -- Add OAuth authorization flows.
