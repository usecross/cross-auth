---
release type: minor
---

A session's `last_active_at` now shows when the session was last used. Before,
it moved only at sign-in and on a sliding refresh, so with `update_age` of a day
it could be a day old for a session in use, and without `update_age` it never
moved.

A request that uses the session, by cookie or bearer token, now updates
`last_active_at` once it is at least `activity_interval` seconds old: five
minutes by default. This writes only `last_active_at`: the session's expiry and
cookie are unchanged, and `update_age` still decides when a session slides. A
session in use costs at most one write per interval. Set the interval with:

```python
CrossAuth(..., config={"session": {"activity_interval": 60}})
```

It is an int from `0`, which records every request, to a year, and `None` keeps
the previous behavior; anything else raises `ValueError`. A failed update is
logged and does not fail the request.

The SQLModel session storage records activity. A custom session storage needs a
new `record_activity(session_id, *, last_active_at, since)` method to do so,
which the storage docs describe; without one, its sessions keep the previous
behavior. Its `refresh` should then also keep a stored `last_active_at` later
than the one it is given.
