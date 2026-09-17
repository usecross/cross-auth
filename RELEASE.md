---
release type: patch
---

Sliding session refresh now atomically rejects revoked or expired sessions. A
revocation between the initial lookup and refresh no longer authenticates the
request or extends its cookie. Custom session adapters must make `refresh`
conditional on an unrevoked session whose stored expiry is at or after the
supplied `updated_at`; rejected refreshes return `None` without changing
storage.
