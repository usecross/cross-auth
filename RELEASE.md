---
release type: minor
---

This release adds session-based social login support to `CrossAuth` and the
FastAPI integration.

Highlights:

- add a browser-session OAuth flow so social login can complete directly into a
  session cookie
- expand the FastAPI example app to demonstrate password login, social login,
  session account linking, and the separate SPA auth-code flow together
- add end-to-end coverage for the FastAPI + SPA example setup
