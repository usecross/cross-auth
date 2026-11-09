---
release type: minor
---

`authenticate_session_token(token)`, on `Context` and on the FastAPI
`CrossAuth`, looks a session token up without a request. It returns an
`AuthenticatedSession` with the active session record and its user, or `None`
when the token is unknown, revoked or expired, or when the accounts storage no
longer returns the user. Sliding sessions are refreshed as they are for
requests. It never calls `get_user_from_request`, so a resolver that also
accepts other credentials can use it for session tokens.

Pass `db_session` to load the user in your own database session. The user then
belongs to that session: its relationships load lazily, and you can change and
commit it. The session lookup and any sliding refresh still run first, in the
session storage's own sessions, and Cross-Auth never commits or closes yours.
This uses the new `with_read_session(session)` method of the SQLModel accounts
storage, which returns a copy of the storage whose user lookups run in
`session`. Accounts storages without it raise `TypeError` when you pass
`db_session`.
