---
title: Session Authentication
description: Manage user sessions with secure cookies.
order: 2
section: Guides
---

## Overview

Session-based authentication is the traditional approach for server-rendered web
applications. After a user logs in with their email and password, the server
creates a session and sends an opaque session-token cookie to the browser.
Subsequent requests include this cookie, allowing the server to identify the
user.

Cross-Auth provides a high-level `CrossAuth` class with `login()` and `logout()`
methods for framework integrations, as well as lower-level functions for custom
session management.

## Using the CrossAuth Class (Recommended)

The FastAPI `CrossAuth` class bundles session creation, cookie management, and
cleanup into simple methods:

### Authenticate and Login

```python
from cross_auth.fastapi import CrossAuth
from fastapi.responses import JSONResponse

auth = CrossAuth(
    providers=[],
    storage=secondary_storage,
    accounts_storage=accounts_storage,
    session_storage=session_storage,
    trusted_origins=["https://myapp.com"],
)

# Verify credentials
user = auth.authenticate(email, password)
if user is None:
    # Invalid credentials
    ...

# Create session + set cookie in one step
response = JSONResponse({"user": user.id})
auth.login(str(user.id), response=response)
```

### Logout

```python
from fastapi import Request

# Revoke session + clear cookie in one step
response = JSONResponse({"ok": True})
auth.logout(request, response=response)
```

### Get Current User

`get_current_user` and `require_current_user` take only the request, so they
work as FastAPI dependencies and as plain calls — in shared-context builders,
GraphQL resolvers, or template helpers — with a single API:

```python
from typing import Annotated

from fastapi import Depends


@app.get("/me")
def me(user: Annotated[User | None, Depends(auth.get_current_user)]): ...


@app.get("/protected")
def protected(
    user: Annotated[User, Depends(auth.require_current_user)],
): ...  # raises 401 if not logged in


def build_context(request: Request) -> dict:  # outside dependency injection
    return {"user": auth.get_current_user(request)}
```

### Sliding Sessions

With `update_age` configured, reads refresh the stored session record — and the
browser's cookie must be re-sent so its `Max-Age` slides too. Install
`SessionCookieMiddleware` once and rolled cookies are delivered on whatever
response the handler produces, including responses returned directly (redirects,
streaming, server-rendered pages):

```python
from cross_auth.fastapi import SessionCookieMiddleware

app.add_middleware(SessionCookieMiddleware)
```

Without `update_age` the middleware is inert and can be omitted. If a session
refreshes and the middleware is missing, Cross-Auth emits a warning instead of
silently letting the browser cookie lapse. A cookie the handler already set
itself — `logout()` clearing it, `login()` replacing it — always wins over the
rolled copy.

`session_storage` is optional when constructing `CrossAuth`, but session-backed
features require it. `login()`, `logout()`, and session-management methods raise
clearly when no `session_storage` is configured. The built-in `/token` endpoint
is still registered, but successful token issuance requires `session_storage`.

## Lower-Level Session Functions

For custom frameworks or advanced use cases, Cross-Auth also exposes plain
functions for session management.

### Authenticating Users

The `authenticate` function verifies an email/password combination against your
user storage:

```python
from cross_auth._password import authenticate

user = authenticate(email, password, accounts_storage)

if user is None:
    # Invalid credentials
    ...
```

This function uses **constant-time verification** -- it always runs bcrypt even
for non-existent users, preventing timing attacks that could enumerate valid
email addresses.

### Creating Sessions

After authentication, create a session to persist the login:

```python
from cross_auth._session import create_session

session_token, session_record = create_session(str(user.id), session_storage)
```

The session token is a cryptographically secure random value
(`secrets.token_urlsafe(32)`, ~256 bits of entropy). Cross-Auth stores only a
hash of that token in `SessionStorage`, together with the session metadata and
expiry.

#### Session Fixation Protection

Always create a **new** session after authentication. Never reuse an existing
session token from before login -- this prevents session fixation attacks.

### Reading Sessions

Retrieve a session by its token:

```python
from cross_auth._session import get_session

session = get_session(session_token, session_storage)

if session is None:
    # Session not found or expired
    ...

print(session.user_id)
print(session.created_at)
print(session.status)
```

### Deleting Sessions

Revoke a session to log the user out:

```python
from cross_auth._session import delete_session

delete_session(session_token, session_storage)
```

This revokes the stored session record. It is a no-op if the session doesn't
exist.

### Bearer Tokens

The built-in OAuth `/token` endpoint issues the same kind of opaque session
token that `create_session()` returns. API clients send it with
`Authorization: Bearer ...`, and Cross-Auth resolves it through
`SessionStorage`.

For clients that authenticate outside `/token` and outside a browser — a GraphQL
sign-in mutation for a native app, a CLI — mint the token directly:

```python
token, record = auth.issue_session_token(
    str(user.id),
    max_age=60 * 60 * 24 * 30,  # e.g. longer-lived mobile sessions
    metadata={"client_name": "ios"},
)
```

The client sends it as `Authorization: Bearer ...` and `get_current_user`
resolves it like any other session. No cookie is set; the `session.issue` hooks
run around the creation, so policy and audit handlers cover this path too.

Because bearer tokens are session records, they are revocable with the same
session-management APIs. Cross-Auth does not issue JWT access tokens by default.

### Cookie Helpers

Cross-Auth provides helpers to create properly configured session cookies:

#### Setting the Session Cookie

```python
from cross_auth._session import make_session_cookie

cookie = make_session_cookie(session_token)
# cookie.name = "session_id"
# cookie.secure = True
# cookie.httponly = True
# cookie.samesite = "lax"
# cookie.path = "/"
```

#### Clearing the Session Cookie

```python
from cross_auth._session import make_clear_cookie

cookie = make_clear_cookie()
# cookie.value = ""
# cookie.max_age = 0
```

#### Custom Configuration

Pass a `SessionConfig` to override defaults:

```python
from cross_auth import SessionConfig
from cross_auth._session import make_session_cookie

config: SessionConfig = {
    "max_age": 3600,  # 1 hour
    "cookies": {
        "name": "my_app_session",
        "secure": True,
        "httponly": True,
        "samesite": "strict",
        "path": "/",
        "domain": ".example.com",
    },
}

cookie = make_session_cookie(session_token, config)
```

## Cookie Defaults

| Setting            | Default        | Notes                                  |
| ------------------ | -------------- | -------------------------------------- |
| `max_age`          | `86400` (24h)  | Session lifetime in seconds            |
| `cookies.name`     | `"session_id"` | Name of the cookie                     |
| `cookies.secure`   | `True`         | Only sent over HTTPS                   |
| `cookies.httponly` | `True`         | Not accessible via JavaScript          |
| `cookies.samesite` | `"lax"`        | Prevents CSRF on cross-origin requests |
| `cookies.path`     | `"/"`          | Cookie is valid for all paths          |
| `cookies.domain`   | `None`         | Scoped to the current domain           |
