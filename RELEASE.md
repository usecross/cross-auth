---
release type: minor
---

This release adds session support via the FastAPI `CrossAuth` class
(`cross_auth.fastapi.CrossAuth`) with high-level `login()` and `logout()`
methods for session management.

- `CrossAuth` class with `authenticate()`, `login()`, `logout()`,
  `get_current_user()`, and `require_current_user()` public methods
- `login(user_id)` creates a session and returns a ready-to-use `Cookie`
- `logout(request)` deletes the session and returns a clear `Cookie`
- `get_current_user()` as a FastAPI dependency with optional `raise_on_missing`
- Server-side session expiry via `expires_at`, enforced on read
- Constant-time password comparison to prevent timing attacks
- `SessionData`, `SessionConfig`, `AccountsStorage`, and `SecondaryStorage`
  exported from `cross_auth`
