---
release type: minor
---

`auth.router` now mounts `POST /logout` whenever `session_storage` is
configured. It revokes the caller's session and answers `204 No Content` with a
cleared session cookie. The session token comes from the session cookie or from
`Authorization: Bearer ...`, so the route logs out browser sessions and bearer
tokens from `/token` or `auth.issue_session_token()` alike:

```python
app.include_router(auth.router, prefix="/api/v1")
# POST /api/v1/logout
```

The route answers 204 also when the request has no token, or one that is
unknown, expired, or already revoked, so a client that answers 401 by logging
out cannot loop. Only a `logout` before hook that raises `CrossAuthException`
changes the response.

`BeforeLogoutEvent` has a new `session_token` field with the token Cross-Auth
found. Return the event with a different `session_token` to revoke that session
instead, for example when your client sends the token in another header. A
returned `session_record` still takes precedence.

`auth.logout()` runs the same code as the route, so it now also revokes a
session sent as `Authorization: Bearer ...` when the request has no valid
session cookie. It no longer rolls a sliding session forward before revoking it.

If you protect `auth.router` with a CSRF dependency, note the new `logout`
operation ID: cookie requests to it need the same protection as your other
browser mutations.
