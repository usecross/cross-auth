---
release type: minor
---

**Breaking:** revoking sessions now leaves expired sessions alone, and revoking
a session runs the new `session.revoke` hooks.

- `SessionStorage.revoke()` and `revoke_all_for_user()` only revoke sessions
  that are still active at `revoked_at`. An expired session keeps its `expired`
  status instead of becoming `revoked`, and `revoke_all_for_user()` counts only
  the sessions it actually ended. `POST /sessions/revoke-others`,
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
  routes answer with that error. The after event's `revoked_count` says how many
  active sessions were revoked. Logging out still runs only the `logout` hooks.

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
