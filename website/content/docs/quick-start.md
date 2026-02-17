---
title: Quick Start
description:
  Get up and running with Cross-Auth session authentication in minutes.
order: 3
section: Getting Started
---

## Overview

This guide walks you through adding email/password login to a FastAPI
application using Cross-Auth's `CrossAuth` class. The class provides high-level
`login()` and `logout()` methods that handle session creation, deletion, and
cookie management for you.

## Step 1: Implement Storage

Cross-Auth uses protocol classes to abstract storage. You need two
implementations:

- **`AccountsStorage`** -- For looking up users by email or ID.
- **`SecondaryStorage`** -- For storing sessions (Redis, in-memory dict,
  database, etc.).

```python
from cross_auth import AccountsStorage, SecondaryStorage


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

## Step 2: Create the CrossAuth Instance

```python
from cross_auth.fastapi import CrossAuth

auth = CrossAuth(
    providers=[],
    storage=session_storage,
    accounts_storage=accounts_storage,
    create_token=lambda _: ("", 0),
    trusted_origins=["https://myapp.com"],
)
```

## Step 3: Login

```python
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()
app.include_router(auth.router)


@app.post("/login")
def login(email: str, password: str):
    user = auth.authenticate(email, password)
    if user is None:
        return JSONResponse({"error": "Invalid credentials"}, status_code=401)

    response = JSONResponse({"user": user.id})
    auth.login(str(user.id), response=response)
    return response
```

## Step 4: Logout

```python
@app.post("/logout")
def logout(request: Request):
    response = JSONResponse({"ok": True})
    auth.logout(request, response=response)
    return response
```

## Step 5: Get the Current User

```python
from typing import Annotated

from fastapi import Depends


@app.get("/me")
def me(user: Annotated[User | None, Depends(auth.get_current_user)]):
    if user is None:
        return {"user": None}
    return {"user": user.id}


@app.get("/protected")
def protected(user: Annotated[User, Depends(auth.require_current_user)]):
    return {"user": user.id}  # raises 401 if not logged in
```

## Next Steps

- [Session Authentication](/docs/session-authentication) -- Full guide on
  session management.
- [Storage](/docs/storage) -- How to implement the storage protocols.
- [OAuth 2.0](/docs/oauth) -- Add OAuth authorization flows.
