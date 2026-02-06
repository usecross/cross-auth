---
title: Models
description: API reference for data models and types.
order: 3
section: API Reference
---

## SessionData

Pydantic model stored in `SecondaryStorage` as JSON under the key
`session:{session_id}`.

```python
from cross_auth import SessionData
```

### Fields

| Field        | Type            | Description                         |
| ------------ | --------------- | ----------------------------------- |
| `user_id`    | `str`           | The ID of the authenticated user.   |
| `created_at` | `AwareDatetime` | When the session was created (UTC). |
| `expires_at` | `AwareDatetime` | When the session expires (UTC).     |

---

## SessionConfig

TypedDict for configuring session cookie behavior. All fields are optional.

```python
from cross_auth import SessionConfig
```

### Fields

| Field         | Type                          | Default        | Description                              |
| ------------- | ----------------------------- | -------------- | ---------------------------------------- |
| `cookie_name` | `str`                         | `"session_id"` | Name of the session cookie.              |
| `max_age`     | `int`                         | `86400`        | Cookie lifetime in seconds (24 hours).   |
| `secure`      | `bool`                        | `True`         | Only send cookie over HTTPS.             |
| `httponly`    | `bool`                        | `True`         | Prevent JavaScript access to the cookie. |
| `samesite`    | `"lax" \| "strict" \| "none"` | `"lax"`        | SameSite cookie attribute.               |
| `path`        | `str`                         | `"/"`          | URL path the cookie is valid for.        |
| `domain`      | `str \| None`                 | `None`         | Domain the cookie is valid for.          |

### Example

```python
config: SessionConfig = {
    "cookie_name": "my_app_session",
    "max_age": 3600,
    "secure": True,
    "samesite": "strict",
    "domain": ".example.com",
}
```
