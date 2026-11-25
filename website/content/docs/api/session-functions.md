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

Verifies email/password credentials. Returns the `User` or `None`. Once the
password matches, raises `CrossAuthException` for a user `user_can_authenticate`
refuses.

### `login(user_id, response=...)`

Creates a session and sets the session cookie directly on the provided FastAPI
`Response`. Raises `CrossAuthException` for a user `user_can_authenticate`
refuses, before the `login` hooks run.

### `logout(request, response=...)`

Reads the session cookie from the request, revokes the session, and sets a
clear-cookie directive on the provided FastAPI `Response`.

### `before(event)`

Registers a typed hook that runs before a Cross-Auth lifecycle event.

### `after(event)`

Registers a typed hook that runs after a Cross-Auth lifecycle event succeeds.

### `get_current_user(request)`

A bound method usable as a FastAPI dependency. Resolves the current user from
the session cookie or `Authorization: Bearer ...` header. Returns `User | None`;
`None` also for a user `user_can_authenticate` refuses.

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

Revokes one session record owned by the user and returns whether it did. An
expired or already revoked session is left as it is.

### `revoke_other_sessions(user_id=..., keep_session_id=...)`

Revokes all of a user's active sessions except one session ID and returns the
number of revoked sessions.

### `revoke_all_sessions(user_id=...)`

Revokes all active sessions for a user and returns the number of revoked
sessions.

### `change_password(request, current_password=..., new_password=..., revoke_other_sessions=True)`

Changes the password of the user the request's session signs in, once
`current_password` matches (`None` only for a user without a password), and
returns the updated user. The accounts storage hashes and stores the new
password. Then it revokes the user's other sessions, keeping the request's own,
unless `revoke_other_sessions` is `False`. Raises `CrossAuthException`:
`unauthorized` (401) without a session, `invalid_password` (400) for a wrong
current password, and `password_too_long` (400) from the SQLModel storage for a
password over bcrypt's 72 bytes. The accounts storage needs a `set_password`
method, as the SQLModel one has; without one it raises `TypeError`. See
[Change a Password](/docs/session-authentication#change-a-password).

The three revoke methods run the
[`session.revoke` hooks](/docs/hooks#sessionrevoke) with `request` set to
`None`. Expired sessions keep their `expired` status and are not counted.

Session methods require `session_storage` to be configured. `auth.router` serves
the caller's own sessions over HTTP with the same storage; see
[List and Revoke Sessions](/docs/session-authentication#list-and-revoke-sessions).

### `get_device_authorization(user_code)`

Returns the pending device authorization request `user_code` belongs to, as a
`DeviceAuthorization` (`client_id`, `client_name`, `scope`, `ip`, `user_agent`,
`metadata`, `created_at`, `expires_at`), or `None` for an unknown or expired
code, one already approved or denied, and one whose client `get_client` no
longer returns. Case and separators in `user_code` are ignored.

### `approve_device_authorization(user_code, user_id=...)`

Approves the request for `user_id` and returns `True`, or returns `False` and
changes nothing in the cases `get_device_authorization` returns `None`. Of
concurrent approvals and denials only one returns `True`. Raises
`CrossAuthException` for a user `user_can_authenticate` refuses, or from a
[`device.approve`](/docs/hooks#deviceapprove) before hook, and the request stays
pending. The session is created when the device next polls `/token`.

### `deny_device_authorization(user_code, user_id=...)`

Denies the request, so the device's next poll gets `access_denied`. Returns as
`approve_device_authorization` does.

The device methods need `OAuthServer(device=DeviceGrant(...))` and raise
`RuntimeError` without it; see
[Device Authorization Grant](/docs/oauth#device-authorization-grant).

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
