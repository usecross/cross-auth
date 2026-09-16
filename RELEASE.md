---
release type: patch
---

Social accounts with `is_login_method=False` can no longer authenticate through
browser, authorization-code, or native ID-token sign-in. Rejected attempts leave
stored credentials unchanged and issue no session or authorization code.
Authenticated account connection and linking remain available.
