---
release type: minor
---

This release updates the FastAPI session API so `CrossAuth.login()` and
`CrossAuth.logout()` set cookies directly on a provided `Response` rather than
returning cookie objects. Tests and docs were updated to reflect the new usage.
