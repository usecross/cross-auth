---
release type: minor
---

This release adds built-in storage adapters, normalizes emails across every
lookup and signup, and hardens transient OAuth state so abandoned flows don't
linger and callbacks can't be replayed.

- **Built-in storage adapters**: `SQLModelSessionStorage` and
  `SQLModelAccountsStorage` (`cross-auth[sqlmodel]`) implement the session and
  accounts storage protocols on your own SQLModel models, with signup hooks
  (`build_user`, `on_signup`, `after_signup`), query filters, keyset cursor
  pagination that raises `InvalidCursorError` for bad cursors, and model
  validation at construction. `RedisStorage` (`cross-auth[redis]`) implements
  `SecondaryStorage` on a synchronous redis-py client.
- Emails are now trimmed and lowercased before every user lookup and creation —
  password login, the token endpoint, OAuth signup, and account linking all go
  through it. Pass `normalize_email=` to `CrossAuth` to customize the
  normalization.
- Transient OAuth state (authorization requests, auth codes, link codes) is now
  stored with a 10-minute TTL, so abandoned flows no longer accumulate in
  storage. The authorization-request state is also single-use: it's consumed on
  the callback, so a replayed callback is rejected instead of staying valid
  until the TTL expires.
- New public helpers: `session_status`, the canonical active/expired/revoked
  derivation used by the storage adapters, and `normalize_email`.

**Upgrade note:** if you're upgrading from 0.16 or earlier and any stored emails
aren't already lowercase, backfill them before upgrading — e.g.
`UPDATE "user" SET email = lower(trim(email))` — and resolve any duplicate rows
that produces. Skipping this means existing users with non-lowercase stored
emails will fail password login, and OAuth sign-ins can create duplicate
accounts instead of matching the existing one.
