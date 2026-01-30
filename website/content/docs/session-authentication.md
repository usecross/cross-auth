---
title: Session Authentication
description: Manage user sessions with secure cookies.
order: 2
section: Guides
---

## Overview

Session-based authentication is the traditional approach for server-rendered web applications. After a user logs in with their email and password, the server creates a session and sends a session ID cookie to the browser. Subsequent requests include this cookie, allowing the server to identify the user.

Cross-Auth provides plain functions for session management -- no framework-specific middleware required.

## Authenticating Users

The `authenticate` function verifies an email/password combination against your user storage:

```python
from cross_auth import authenticate

user = authenticate(email, password, accounts_storage)

if user is None:
    # Invalid credentials
    ...
```

This function uses **constant-time verification** -- it always runs bcrypt even for non-existent users, preventing timing attacks that could enumerate valid email addresses.

## Creating Sessions

After authentication, create a session to persist the login:

```python
from cross_auth import create_session

session_id, session_data = create_session(str(user.id), session_storage)
```

The session ID is a cryptographically secure random token (`secrets.token_urlsafe(32)`, ~192 bits of entropy). Session data is stored in your `SecondaryStorage` under the key `session:{session_id}`.

### Session Fixation Protection

Always create a **new** session after authentication. Never reuse an existing session ID from before login -- this prevents session fixation attacks.

## Reading Sessions

Retrieve a session by its ID:

```python
from cross_auth import get_session

session = get_session(session_id, session_storage)

if session is None:
    # Session not found or expired
    ...

print(session.user_id)
print(session.created_at)
```

## Deleting Sessions

Delete a session to log the user out:

```python
from cross_auth import delete_session

delete_session(session_id, session_storage)
```

This is a no-op if the session doesn't exist.

## Cookie Helpers

Cross-Auth provides helpers to create properly configured session cookies:

### Setting the Session Cookie

```python
from cross_auth import make_session_cookie

cookie = make_session_cookie(session_id)
# cookie.name = "session_id"
# cookie.secure = True
# cookie.httponly = True
# cookie.samesite = "lax"
# cookie.path = "/"
```

### Clearing the Session Cookie

```python
from cross_auth import make_clear_cookie

cookie = make_clear_cookie()
# cookie.value = ""
# cookie.max_age = 0
```

### Custom Configuration

Pass a `SessionConfig` to override defaults:

```python
from cross_auth import SessionConfig, make_session_cookie

config: SessionConfig = {
    "cookie_name": "my_app_session",
    "max_age": 3600,       # 1 hour
    "secure": True,
    "httponly": True,
    "samesite": "strict",
    "path": "/",
    "domain": ".example.com",
}

cookie = make_session_cookie(session_id, config)
```

## Cookie Defaults

| Setting | Default | Notes |
|---------|---------|-------|
| `cookie_name` | `"session_id"` | Name of the cookie |
| `max_age` | `86400` (24h) | Session lifetime in seconds |
| `secure` | `True` | Only sent over HTTPS |
| `httponly` | `True` | Not accessible via JavaScript |
| `samesite` | `"lax"` | Prevents CSRF on cross-origin requests |
| `path` | `"/"` | Cookie is valid for all paths |
| `domain` | `None` | Scoped to the current domain |
