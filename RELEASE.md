---
release type: patch
---

FastAPI applications using sliding sessions now authenticate users and renew
session cookies from one consistent session lookup. This prevents session
changes between cookie renewal and user loading while preserving existing
cookie, bearer token, and custom request resolver behavior.
