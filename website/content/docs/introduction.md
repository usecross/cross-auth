---
title: Introduction
description: Cross-Auth is a framework-agnostic authentication library for Python web applications.
order: 1
section: Getting Started
---

## What is Cross-Auth?

Cross-Auth is a framework-agnostic authentication library for Python web applications. It provides the building blocks for implementing secure authentication flows, including OAuth 2.0, session-based authentication, and social login.

Cross-Auth works with any Python web framework -- Django, Flask, FastAPI, and others -- by providing plain functions and storage protocols rather than framework-specific decorators or middleware.

## Key Features

- **Session-based authentication** -- Authenticate users with email/password and manage sessions via secure cookies.
- **OAuth 2.0** -- Full authorization code flow with PKCE support.
- **Social login** -- Connect with providers like GitHub, Google, and more.
- **Secure by default** -- Constant-time password verification, HttpOnly cookies, and SameSite protection out of the box.
- **Storage agnostic** -- Bring your own database. Implement the storage protocol with SQLAlchemy, Django ORM, MongoDB, or anything else.

## How It Works

Cross-Auth separates concerns into three layers:

1. **Storage protocols** -- Define how users and sessions are persisted. You implement these for your database.
2. **Core functions** -- Plain Python functions for authentication, session management, and token issuance.
3. **Framework integration** -- Optional route handlers and middleware for your web framework of choice.

```python
from cross_auth import authenticate, create_session, make_session_cookie

# Authenticate a user
user = authenticate(email, password, accounts_storage)

# Create a session
session_id, session_data = create_session(str(user.id), session_storage)

# Get a cookie to send to the browser
cookie = make_session_cookie(session_id)
```

## Next Steps

- [Installation](/docs/installation) -- Add Cross-Auth to your project.
- [Quick Start](/docs/quick-start) -- Build a login flow in minutes.
