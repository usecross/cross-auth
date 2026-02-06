---
title: Session Functions
description: API reference for session management functions.
order: 2
section: API Reference
---

## create_session()

Creates a new session in storage and returns the session ID and data.

```python
from cross_auth import create_session

session_id, session_data = create_session(user_id, storage, max_age=86400)
```

### Parameters

| Parameter | Type               | Default | Description                       |
| --------- | ------------------ | ------- | --------------------------------- |
| `user_id` | `str`              | —       | The ID of the authenticated user. |
| `storage` | `SecondaryStorage` | —       | Storage backend for sessions.     |
| `max_age` | `int`              | `86400` | Session lifetime in seconds.      |

### Returns

`tuple[str, SessionData]` -- The session ID and session data.

---

## get_session()

Retrieves a session from storage by its ID.

```python
from cross_auth import get_session

session = get_session(session_id, storage)
```

### Parameters

| Parameter    | Type               | Description                     |
| ------------ | ------------------ | ------------------------------- |
| `session_id` | `str`              | The session ID from the cookie. |
| `storage`    | `SecondaryStorage` | Storage backend for sessions.   |

### Returns

`SessionData | None` -- The session data, or `None` if not found.

---

## delete_session()

Deletes a session from storage. No-op if the session doesn't exist.

```python
from cross_auth import delete_session

delete_session(session_id, storage)
```

### Parameters

| Parameter    | Type               | Description                   |
| ------------ | ------------------ | ----------------------------- |
| `session_id` | `str`              | The session ID to delete.     |
| `storage`    | `SecondaryStorage` | Storage backend for sessions. |

---

## make_session_cookie()

Creates a `Cookie` object with the session ID and secure defaults.

```python
from cross_auth import make_session_cookie

cookie = make_session_cookie(session_id, config=None)
```

### Parameters

| Parameter    | Type                    | Default | Description                            |
| ------------ | ----------------------- | ------- | -------------------------------------- |
| `session_id` | `str`                   | —       | The session ID to store in the cookie. |
| `config`     | `SessionConfig \| None` | `None`  | Optional configuration overrides.      |

### Returns

`Cookie` -- A cookie object ready to be sent to the browser.

---

## make_clear_cookie()

Creates a `Cookie` object that clears the session cookie (empty value,
`max_age=0`).

```python
from cross_auth import make_clear_cookie

cookie = make_clear_cookie(config=None)
```

### Parameters

| Parameter | Type                    | Default | Description                                                                                            |
| --------- | ----------------------- | ------- | ------------------------------------------------------------------------------------------------------ |
| `config`  | `SessionConfig \| None` | `None`  | Optional configuration (uses same `name`, `path`, `domain` so the browser matches the correct cookie). |

### Returns

`Cookie` -- A cookie object that instructs the browser to delete the session
cookie.
