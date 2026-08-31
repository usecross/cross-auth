---
release type: patch
---

Password authentication now uses consistent timing-safe checks for existing,
unknown, and passwordless accounts through both `CrossAuth.authenticate` and the
OAuth password grant. This reduces account-enumeration risk without changing
successful or failed authentication responses.
