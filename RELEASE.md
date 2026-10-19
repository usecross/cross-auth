---
release type: patch
---

Share the internal session-login implementation between browser OAuth callbacks
and programmatic FastAPI login, preserving their existing hook, cookie, and
metadata behavior. Add regression coverage for both login paths and execution
without FastAPI or Starlette imports.
