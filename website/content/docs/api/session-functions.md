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

Reads the session cookie from the request, revokes the session, and sets a
clear-cookie directive on the provided FastAPI `Response`.

### `before(event)`

Registers a typed hook that runs before a Cross-Auth lifecycle event.

### `after(event)`

Registers a typed hook that runs after a Cross-Auth lifecycle event succeeds.

### `get_current_user(request)`

A bound method usable as a FastAPI dependency. Resolves the current user from
the session cookie or `Authorization: Bearer ...` header. Returns `User | None`.

### `require_current_user(request)`

A bound method usable as a FastAPI dependency. Same as `get_current_user` but
raises a 401 `HTTPException` if no user is found. Returns `User`.

### `list_sessions(user_id, ...)`

Lists session records for a user. Supports status filters, ordering, limits, and
cursors through the configured `SessionStorage`.

### `get_session(session_id, user_id=...)`

Returns one session record for the user, or `None` if the session does not exist
or belongs to a different user.

### `revoke_session(session_id, user_id=...)`

Revokes one session record owned by the user.

### `revoke_other_sessions(user_id=..., keep_session_id=...)`

Revokes all of a user's sessions except one session ID and returns the number of
revoked sessions.

### `revoke_all_sessions(user_id=...)`

Revokes all sessions for a user and returns the number of revoked sessions.

Session methods require `session_storage` to be configured.

---

## Low-Level Functions

These functions from `cross_auth._session` are used internally and can be
imported directly for custom framework integrations.

### create_session()

Creates a new session in storage and returns the opaque session token and
session record.

```python
from cross_auth._session import create_session

session_token, session_record = create_session(user_id, storage, max_age=86400)
```

#### Parameters

| Parameter | Type             | Default | Description                       |
| --------- | ---------------- | ------- | --------------------------------- |
| `user_id` | `str`            | —       | The ID of the authenticated user. |
| `storage` | `SessionStorage` | —       | Storage backend for sessions.     |
| `max_age` | `int`            | `86400` | Session lifetime in seconds.      |

#### Returns

`tuple[str, SessionRecord]` -- The opaque session token and session record.

---

### get_session()

Retrieves a session from storage by its opaque token.

```python
from cross_auth._session import get_session

session = get_session(session_token, storage)
```

#### Parameters

| Parameter       | Type             | Description                          |
| --------------- | ---------------- | ------------------------------------ |
| `session_token` | `str`            | The token from a cookie or header.   |
| `storage`       | `SessionStorage` | Storage backend for session records. |

#### Returns

`SessionRecord | None` -- The session record, or `None` if not found, expired,
or revoked.

---

### delete_session()

Revokes a session in storage. No-op if the session doesn't exist.

```python
from cross_auth._session import delete_session

delete_session(session_token, storage)
```

#### Parameters

| Parameter       | Type             | Description                          |
| --------------- | ---------------- | ------------------------------------ |
| `session_token` | `str`            | The session token to revoke.         |
| `storage`       | `SessionStorage` | Storage backend for session records. |

---

### make_session_cookie()

Creates a `Cookie` object with the session token and secure defaults.

```python
from cross_auth._session import make_session_cookie

cookie = make_session_cookie(session_token, config=None)
```

#### Parameters

| Parameter       | Type                    | Default | Description                               |
| --------------- | ----------------------- | ------- | ----------------------------------------- |
| `session_token` | `str`                   | —       | The session token to store in the cookie. |
| `config`        | `SessionConfig \| None` | `None`  | Optional configuration overrides.         |

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
