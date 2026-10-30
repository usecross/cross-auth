---
release type: minor
---

Django apps can now list and revoke a user's sessions. Opt in with Cross Auth's
session engine and middleware, in place of Django's:

```python
SESSION_ENGINE = "cross_auth.django.sessions"
MIDDLEWARE = [
    # Instead of django.contrib.sessions.middleware.SessionMiddleware:
    "cross_auth.django.sessions.SessionMiddleware",
    # ...
]
```

Sessions then live in the new `cross_auth.django.models.Session` table (run
`migrate`), which records each session's user, `login_method` (the provider for
Cross Auth sign-ins, `None` for other logins such as Django's password login),
user agent, IP, `created_at`, `last_activity` and a `public_id` to name it on
your pages (never show the session key: it is the cookie). Each login starts a
new `created_at` and `public_id`; a new session key without a login, such as
after a password change, keeps them. `last_activity` is updated at most once per
`CROSS_AUTH["SESSION_ACTIVITY_INTERVAL"]` seconds (default 60). Existing
sessions in `django_session` are not moved, so users sign in again after the
switch. Only the database engine is provided; there is no cache or `cached_db`
variant.

```python
from cross_auth.django.sessions import (
    list_sessions,
    revoke_other_sessions,
    revoke_session,
)

sessions = list_sessions(request)  # the user's active sessions, newest first
revoke_session(request, sessions[0].id)  # never another user's session
revoke_other_sessions(request)  # keeps the current one
```

Django's `check` warns (`cross_auth.W002`, `cross_auth.W003`) when the engine is
used without the middleware or the other way round.
