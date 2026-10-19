---
release type: patch
---

Move native ID-token sign-in into an internal, framework-independent module
while preserving the existing FastAPI API and authentication behavior. Add
regression coverage for core sign-in, hook ordering, and operation without
FastAPI or Starlette imports.
