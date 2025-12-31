---
release type: minor
---

Add secure account linking for social authentication providers.

**New features:**

- Manual account linking via `response_type=link_code` flow
- Automatic account linking by email (when enabled)
- Configurable `account_linking` settings:
  - `enabled`: Enable/disable account linking
  - `allow_different_emails`: Allow linking accounts with different emails

**Security improvements:**

- Fail fast at authorize time if linking is disabled (better UX)
- Email verification checks for untrusted providers
- Link codes are bound to the user who initiated the flow
