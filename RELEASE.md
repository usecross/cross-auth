---
release type: patch
---

This release lowers the log level for expected OAuth callback errors so they no
longer trigger error-level alerts on routine user actions.

When a user denies consent at the provider (`access_denied`), the OAuth callback
handler now logs at `INFO` instead of `ERROR`. Unexpected provider errors (e.g.
`invalid_request`) continue to be logged at `ERROR`.
