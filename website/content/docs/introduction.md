---
title: Introduction
description:
  Cross-Auth is a framework-agnostic authentication library for Python web
  applications.
order: 1
section: Getting Started
---

## What is Cross-Auth?

Cross-Auth is a framework-agnostic authentication library for Python web
applications. It provides the building blocks for implementing secure
authentication flows, including OAuth 2.0, session-based authentication, and
social login.

Cross-Auth works with any Python web framework -- Django, Flask, FastAPI, and
others -- by providing plain functions and storage protocols rather than
framework-specific decorators or middleware.

## Key Features

- **Session-based authentication** -- Authenticate users with email/password and
  manage sessions via secure cookies.
- **OAuth 2.0** -- Full authorization code flow with PKCE support.
- **Social login** -- Connect with providers like GitHub, Google, and more.
- **Secure by default** -- Constant-time password verification, HttpOnly
  cookies, and SameSite protection out of the box.
- **Storage agnostic** -- Bring your own database. Implement the storage
  protocol with SQLAlchemy, Django ORM, MongoDB, or anything else.

## How It Works

Cross-Auth separates concerns into three layers:

1. **Storage protocols** -- Define how users and sessions are persisted. You
   implement these for your database.
2. **Core functions** -- Plain Python functions for authentication, session
   management, and token issuance.
3. **Framework integration** -- Optional route handlers and middleware for your
   web framework of choice.

```python
from cross_auth.fastapi import CrossAuth
from fastapi import Request
from fastapi.responses import JSONResponse

auth = CrossAuth(
    providers=[],
    storage=session_storage,
    accounts_storage=accounts_storage,
    create_token=lambda _: ("", 0),
    trusted_origins=["https://myapp.com"],
)


# Authenticate + login: creates session + sets cookie on the response
async def login_endpoint(email: str, password: str):
    user = auth.authenticate(email, password)
    response = JSONResponse({"user": user.id})
    auth.login(str(user.id), response=response)
    return response


# Logout: deletes session + clears cookie on the response
async def logout_endpoint(request: Request):
    response = JSONResponse({"message": "logged out"})
    auth.logout(request, response=response)
    return response
```

## Next Steps

- [Installation](/docs/installation) -- Add Cross-Auth to your project.
- [Quick Start](/docs/quick-start) -- Build a login flow in minutes.
- [Hooks](/docs/hooks) -- Extend auth flows with typed lifecycle callbacks.
