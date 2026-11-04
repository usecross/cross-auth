---
release type: minor
---

`auth.router` now lets users list and revoke their own sessions. Whenever
`session_storage` is configured, it mounts these JSON routes next to
`POST /logout`:

| Route                           | Response                    | Operation ID            |
| ------------------------------- | --------------------------- | ----------------------- |
| `GET /sessions`                 | `200` with a `SessionList`  | `list_sessions`         |
| `DELETE /sessions/{session_id}` | `204 No Content`            | `revoke_session`        |
| `POST /sessions/revoke-others`  | `200` with `{"revoked": n}` | `revoke_other_sessions` |

```python
app.include_router(auth.router, prefix="/api/v1")
# GET /api/v1/sessions?limit=50&cursor=...
```

Like `/logout`, the routes act on the session that authenticates the request
(cookie, then bearer token); without one they answer `401`. `GET /sessions`
returns the caller's active sessions newest first, as
`{"sessions": [...], "next_cursor": ...}`. Each session has `id`, `client_id`,
`client_name`, `user_agent`, `ip`, `login_method`, `created_at`, `expires_at`
and `current`, which marks the session that authenticated the request; session
tokens and their hashes are never included. Pages hold 50 sessions by default
and up to 100 with `limit`.

`DELETE /sessions/{session_id}` answers the same `404 session_not_found` for an
unknown id and for another user's session. Revoking the current cookie session
clears the cookie, as `/logout` does. `POST /sessions/revoke-others` revokes
every other session of the caller and keeps the current one.

The routes run no hooks. If you protect `auth.router` with a CSRF dependency,
cookie requests to `revoke_session` and `revoke_other_sessions` need the same
protection as `logout`; the dependency in the security guide already covers
them. If your application serves its own routes at these paths under the same
prefix, remove them or mount `auth.router` elsewhere.
