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

`auth.logout()` runs the same code as the route, so it now also revokes a
session sent as `Authorization: Bearer ...` when the request has no valid
session cookie. It no longer rolls a sliding session forward before revoking it.

Send `{"scope": "all"}` as the JSON body, or call
`auth.logout(request, response=response, scope="all")`, to log out everywhere:
Cross-Auth revokes every session of the caller's user. Both logout events have a
new `scope` field (`"current"` or `"all"`, exported as
`cross_auth.hooks.LogoutScope`), which a before hook may change, and
`AfterLogoutEvent.revoked_count` reports how many sessions were revoked.

If you protect `auth.router` with a CSRF dependency, note the new `logout`
operation ID: cookie requests to it need the same protection as your other
browser mutations.
