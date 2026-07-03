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

## Step 1: Set Up Storage

Cross-Auth needs three storage backends:

- **`SecondaryStorage`** -- For transient OAuth data such as authorization
  codes, PKCE challenges, and link codes.
- **`AccountsStorage`** -- For looking up and creating users.
- **`SessionStorage`** -- For durable, revocable browser sessions and bearer
  tokens.

The built-in adapters cover the common Redis + SQLModel setup. Install the
extras:

```bash
uv add 'cross-auth[redis,sqlmodel]'
```

Use `RedisStorage` for secondary storage, and the SQLModel adapters for your
accounts and sessions. You own the models; the adapters implement the protocols.
See the [Storage](/docs/storage) guide for the model definitions (`User`,
`SocialAccount`, `UserSession`) used below.

```python
import redis
from sqlmodel import Session, create_engine

from cross_auth.storage.redis import RedisStorage
from cross_auth.storage.sqlmodel import (
    SQLModelAccountsStorage,
    SQLModelSessionStorage,
)

# User, SocialAccount and UserSession are your own SQLModel models — see the
# Storage guide for the definitions used here. The "+psycopg" driver needs a
# database driver installed (e.g. `pip install psycopg`).
engine = create_engine("postgresql+psycopg://localhost/myapp")

secondary_storage = RedisStorage(redis.Redis.from_url("redis://localhost:6379"))


accounts_storage = SQLModelAccountsStorage(
    User, SocialAccount, session_factory=lambda: Session(engine)
)
session_storage = SQLModelSessionStorage(
    UserSession, session_factory=lambda: Session(engine)
)
```

Need invite checks, team creation, custom user construction, or post-signup
telemetry? Subclass the accounts storage and override the signup hooks
(`build_user`, `on_signup`, `after_signup`) — see the [Storage](/docs/storage)
guide.

Using a different ORM? The [Storage](/docs/storage) guide shows how to implement
the protocols directly.

## Step 2: Create the CrossAuth Instance

```python
from cross_auth.fastapi import CrossAuth

auth = CrossAuth(
    providers=[],
    storage=secondary_storage,
    accounts_storage=accounts_storage,
    session_storage=session_storage,
    trusted_origins=["https://myapp.com"],
)
```

Emails are trimmed and lowercased before every lookup and signup, so
`Alice@Example.com` and `alice@example.com` are the same account. Pass a
callable as `normalize_email=` to customize this (e.g. to also collapse Gmail
dot-aliases).

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
- [Hooks](/docs/hooks) -- Add typed lifecycle hooks around auth flows.
- [Storage](/docs/storage) -- How to implement the storage protocols.
- [OAuth 2.0](/docs/oauth) -- Add OAuth authorization flows.
