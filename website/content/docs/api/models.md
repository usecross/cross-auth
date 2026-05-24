---
title: Models
description: API reference for data models and types.
order: 3
section: API Reference
---

## SessionRecord

Protocol for durable session rows stored in `SessionStorage`.

```python
from cross_auth import SessionRecord
```

### Fields

| Field            | Type                                 | Description                             |
| ---------------- | ------------------------------------ | --------------------------------------- |
| `id`             | `Any`                                | Stable database ID for the session.     |
| `user_id`        | `Any`                                | The ID of the authenticated user.       |
| `created_at`     | `AwareDatetime`                      | When the session was created (UTC).     |
| `updated_at`     | `AwareDatetime`                      | When the session was last refreshed.    |
| `expires_at`     | `AwareDatetime`                      | When the session expires (UTC).         |
| `last_active_at` | `AwareDatetime \| None`              | Last activity timestamp.                |
| `revoked_at`     | `AwareDatetime \| None`              | When the session was revoked.           |
| `client_id`      | `str \| None`                        | OAuth client ID for bearer tokens.      |
| `client_name`    | `str \| None`                        | Display name for the client.            |
| `user_agent`     | `str \| None`                        | User agent associated with the session. |
| `ip`             | `str \| None`                        | IP address associated with the session. |
| `status`         | `"active" \| "expired" \| "revoked"` | Derived status.                         |

## SessionListResult

Protocol returned by session-listing APIs.

```python
from cross_auth import SessionListResult
```

| Field         | Type                      | Description                 |
| ------------- | ------------------------- | --------------------------- |
| `records`     | `Sequence[SessionRecord]` | Session records for a page. |
| `next_cursor` | `str \| None`             | Cursor for the next page.   |

---

## SessionConfig

TypedDict for configuring session behavior. All fields are optional. Cookie
attributes live in the nested `cookies` field (see `SessionCookieConfig`).

```python
from cross_auth import SessionConfig
```

### Fields

| Field          | Type                   | Default | Description                                                                                                                                                       |
| -------------- | ---------------------- | ------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `max_age`      | `int`                  | `86400` | Session lifetime in seconds (24 hours); also the session cookie's `Max-Age`.                                                                                      |
| `update_age`   | `int \| None`          | `None`  | Sliding-session interval. After this many seconds a read rolls `expires_at` forward; cookie clients also get a fresh `Set-Cookie` so the browser copy slides too. |
| `token_hasher` | `Callable[[str], str]` | SHA-256 | Hash function for persisted tokens.                                                                                                                               |
| `cookies`      | `SessionCookieConfig`  | —       | Session cookie attributes (see below).                                                                                                                            |

### Example

```python
config: SessionConfig = {
    "max_age": 3600,
    "update_age": 600,
    "cookies": {
        "auth": True,
        "name": "my_app_session",
        "secure": True,
        "samesite": "strict",
        "domain": ".example.com",
    },
}
```

---

## SessionCookieConfig

TypedDict for the session cookie's attributes, nested under
`SessionConfig["cookies"]`. All fields are optional.

```python
from cross_auth import SessionCookieConfig
```

### Fields

| Field      | Type                          | Default        | Description                                                                           |
| ---------- | ----------------------------- | -------------- | ------------------------------------------------------------------------------------- |
| `auth`     | `bool`                        | `False`        | Register the `GET /{provider}/login` browser cookie flow. Requires `session_storage`. |
| `name`     | `str`                         | `"session_id"` | Name of the session cookie.                                                           |
| `secure`   | `bool`                        | `True`         | Only send cookie over HTTPS.                                                          |
| `httponly` | `bool`                        | `True`         | Prevent JavaScript access to the cookie.                                              |
| `samesite` | `"lax" \| "strict" \| "none"` | `"lax"`        | SameSite cookie attribute.                                                            |
| `path`     | `str`                         | `"/"`          | URL path the cookie is valid for.                                                     |
| `domain`   | `str \| None`                 | `None`         | Domain the cookie is valid for.                                                       |
