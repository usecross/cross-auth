---
release type: minor
---

The Django integration's `CROSS_AUTH["SESSION_ACTIVITY_INTERVAL"]` now defaults
to 300 seconds, like core's `activity_interval`, instead of 60. A session's
`last_activity` is then updated at most once every five minutes unless the
session is saved. Set it to `60` to keep the previous interval.

Cross-Auth no longer catches errors that a session storage's `record_activity`
raises: the storage keeps recording best-effort itself. The SQLModel session
storage catches SQLAlchemy's errors, logs a warning on the
`cross_auth.storage.sqlmodel` logger instead of `cross_auth._session`, and the
request keeps its session, as before. A custom session storage with
`record_activity` should catch its own database errors, log them and return
`None`; anything else it raises now fails the request.
