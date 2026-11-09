---
release type: patch
---

A sliding-session refresh no longer moves a session's expiry backwards. When two
requests read the same session and both refresh it, the one that committed last
used to write its older `updated_at` and `expires_at` over the newer ones. Now
`refresh` only moves a session forward: if the stored `updated_at` is already at
or after the new one, it returns the session unchanged, and the request stays
signed in. That request no longer re-sends the session cookie either, because
the session's expiry did not move.

Custom `SessionStorage` adapters should do the same: when the stored
`updated_at` is already at or after the `updated_at` passed to `refresh`, return
the session without changing it.

During a rolling deploy, workers still on an older version can move an expiry
backwards until they are replaced.
