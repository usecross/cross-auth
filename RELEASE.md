---
release type: minor
---

In the Django integration, a session that signed a user in now keeps its row
when it ends before it expires, as sessions do in the FastAPI integration. This
applies with `SESSION_ENGINE = "cross_auth.django.sessions"`.

- A logout, `revoke_session`, `revoke_other_sessions`, and Django ending a
  session after a password change no longer delete the session's row. The row
  gets a `revoked_at` time, its session data is emptied, and it stays until it
  would have expired. `clearsessions` then deletes it. An anonymous session that
  ends is deleted, as before.
- The session store treats a revoked row as gone: its cookie loads nothing, and
  a request that still holds the session cannot save it back or move it to a new
  key.
- `DjangoSessionStorage` lists and revokes signed-in browser sessions together
  with bearer tokens. So the OAuth server's `POST logout` with
  `{"scope": "all"}` now ends the user's browser sessions as well as their
  tokens, including a browser session of the sender's own. Without that scope it
  still ends only the request's token.
- `revoke_session` ends the request's own session by its ID before it logs out,
  so a key change by a concurrent request can no longer keep it signed in.
- With `CROSS_AUTH["SESSION_STORE_IP"]` off, a session that ends loses its
  stored IP.

There is no migration: 0.58.0 added the `revoked_at` column.

Upgrade all workers together. A worker on an earlier version does not check
`revoked_at`, so during a rolling deployment a session that a new worker revoked
still works on old workers until they stop, and old workers delete rows instead
of keeping them.

If your own code queries `cross_auth.django.models.Session`, filter on
`revoked_at__isnull=True` to get the sessions that are still signed in.

The Django guide has a new section, "After a password change": Django ends the
user's other browser sessions itself, and their bearer tokens stay until you
call `revoke_other_sessions`.
