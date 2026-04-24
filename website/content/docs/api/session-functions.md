---
title: Session Functions
description: API reference for session management functions.
order: 2
section: API Reference
---

## High-Level API (FastAPI)

The FastAPI `CrossAuth` class provides these public methods for session
management. See [Session Authentication](/docs/session-authentication) for usage
examples.

### `authenticate(email, password)`

Verifies email/password credentials. Returns the `User` or `None`.

### `login(user_id, response=...)`

Creates a session and sets the session cookie directly on the provided FastAPI
`Response`.

### `logout(request, response=...)`

Reads the session cookie from the request, deletes the session, and sets a
clear-cookie directive on the provided FastAPI `Response`.

### `before(event)`

Registers a typed hook that runs before a Cross-Auth lifecycle event.

### `after(event)`

Registers a typed hook that runs after a Cross-Auth lifecycle event succeeds.

### `get_current_user(request)`

A bound method usable as a FastAPI dependency. Resolves the current user from
the session cookie. Returns `User | None`.

### `require_current_user(request)`

A bound method usable as a FastAPI dependency. Same as `get_current_user` but
raises a 401 `HTTPException` if no user is found. Returns `User`.

---

## Low-Level Functions

These functions from `cross_auth._session` are used internally and can be
imported directly for custom framework integrations.

### create_session()

Creates a new session in storage and returns the session ID and data.

```python
from cross_auth._session import create_session

session_id, session_data = create_session(user_id, storage, max_age=86400)
```

#### Parameters

| Parameter | Type               | Default | Description                       |
| --------- | ------------------ | ------- | --------------------------------- |
| `user_id` | `str`              | —       | The ID of the authenticated user. |
| `storage` | `SecondaryStorage` | —       | Storage backend for sessions.     |
| `max_age` | `int`              | `86400` | Session lifetime in seconds.      |

#### Returns

`tuple[str, SessionData]` -- The session ID and session data.

---

### get_session()

Retrieves a session from storage by its ID.

```python
from cross_auth._session import get_session

session = get_session(session_id, storage)
```

#### Parameters

| Parameter    | Type               | Description                     |
| ------------ | ------------------ | ------------------------------- |
| `session_id` | `str`              | The session ID from the cookie. |
| `storage`    | `SecondaryStorage` | Storage backend for sessions.   |

#### Returns

`SessionData | None` -- The session data, or `None` if not found or expired.

---

### delete_session()

Deletes a session from storage. No-op if the session doesn't exist.

```python
from cross_auth._session import delete_session

delete_session(session_id, storage)
```

#### Parameters

| Parameter    | Type               | Description                   |
| ------------ | ------------------ | ----------------------------- |
| `session_id` | `str`              | The session ID to delete.     |
| `storage`    | `SecondaryStorage` | Storage backend for sessions. |

---

### make_session_cookie()

Creates a `Cookie` object with the session ID and secure defaults.

```python
from cross_auth._session import make_session_cookie

cookie = make_session_cookie(session_id, config=None)
```

#### Parameters

| Parameter    | Type                    | Default | Description                            |
| ------------ | ----------------------- | ------- | -------------------------------------- |
| `session_id` | `str`                   | —       | The session ID to store in the cookie. |
| `config`     | `SessionConfig \| None` | `None`  | Optional configuration overrides.      |

#### Returns

`Cookie` -- A cookie object ready to be sent to the browser.

---

### make_clear_cookie()

Creates a `Cookie` object that clears the session cookie (empty value,
`max_age=0`).

```python
from cross_auth._session import make_clear_cookie

cookie = make_clear_cookie(config=None)
```

#### Parameters

| Parameter | Type                    | Default | Description                                                                                            |
| --------- | ----------------------- | ------- | ------------------------------------------------------------------------------------------------------ |
| `config`  | `SessionConfig \| None` | `None`  | Optional configuration (uses same `name`, `path`, `domain` so the browser matches the correct cookie). |

#### Returns

`Cookie` -- A cookie object that instructs the browser to delete the session
cookie.
