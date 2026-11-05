---
release type: minor
---

**Breaking:** revoking sessions now leaves expired sessions alone, and revoking
a session runs the new `session.revoke` hooks (Django: signals).

- `SessionStorage.revoke()` and `revoke_all_for_user()` only revoke sessions
  that are still active at `revoked_at`. An expired session keeps its `expired`
  status instead of becoming `revoked`, and `revoke_all_for_user()` counts only
  the sessions it actually ended. `revoke()` now returns whether it revoked the
  session, and so does `auth.revoke_session()`. `POST /sessions/revoke-others`,
  `auth.revoke_other_sessions()`, `auth.revoke_all_sessions()` and the
  `revoked_count` of a `logout` with `scope="all"` therefore no longer count
  expired sessions. Custom session storages must do the same; see
  [Storage](/docs/storage).
- `GET /sessions` takes `status=active|expired|revoked|all` (default `active`),
  so a UI can show signed-out devices too. Each session now also has `status`,
  `last_active_at` and `revoked_at`.
- `DELETE /sessions/{session_id}`, `POST /sessions/revoke-others`,
  `auth.revoke_session()`, `auth.revoke_other_sessions()` and
  `auth.revoke_all_sessions()` run `session.revoke` before and after hooks. A
  before hook that raises `CrossAuthException` refuses the revocation, and the
  routes answer with that error. The after hook runs only when at least one
  session was revoked, and its `revoked_count` says how many. Logging out still
  runs only the `logout` hooks.
- `logout` after hooks now follow the same rule: they run only when the logout
  revoked a session. A logout without a session, or whose session was already
  revoked or expired, still answers 204, clears the cookie and runs the before
  hook. `AfterLogoutEvent.session_record` is therefore never `None`.
- Django: `cross_auth.django.sessions.revoke_session()` and
  `revoke_other_sessions()` send the new `before_session_revoke` and
  `session_revoked` signals. Raise `PermissionDenied` from a
  `before_session_revoke` receiver to refuse. `session_revoked` is sent only
  when a session was signed out. `revoke_session()` now leaves expired sessions
  alone, like `revoke_other_sessions()` already did.

```python
from cross_auth.hooks import AfterSessionRevokeEvent


@auth.after("session.revoke")
def audit_revocation(event: AfterSessionRevokeEvent) -> None:
    audit_log.record(
        "sessions_revoked",
        user_id=event.user_id,
        scope=event.scope,  # "one", "others" or "all"
        count=event.revoked_count,
    )
```
