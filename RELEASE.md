---
release type: minor
---

Provider connections now support opt-in sharing with
`account_linking.allow_shared_connections=True`. Exclusive ownership remains the
default and requires a unique provider identity. Shared connections require
per-user identity uniqueness and a partial unique login-owner index. The flag
controls application policy; the matching schema enforces concurrent writes.

SQLModel attachment relies on database constraints instead of explicit table
locks. Same-owner creation retries are idempotent. Other failed inserts retain
the original database integrity error. Reconnecting never implicitly enables
login.

Application-owned tables need an explicit migration. See the storage guide for
both schemas and duplicate-detection queries. Custom stores must support scoped
social-account lookups and `has_social_account`, and enforce ownership through
their schema. Unfiltered lookups raise when several connections match.
