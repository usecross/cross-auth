---
release type: minor
---

This release adds initial support for sessions, by providing the following:

- `authenticate()` for verifying email/password credentials with constant-time
  comparison
- `create_session()` / `get_session()` / `delete_session()` for session
  lifecycle management
- Server-side session expiry via `expires_at`, enforced on read
- `make_session_cookie()` / `make_clear_cookie()` helpers for secure cookie
  handling
- `SessionData` and `SessionConfig` types
