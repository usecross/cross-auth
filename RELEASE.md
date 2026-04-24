---
release type: minor
---

This release adds a typed lifecycle hook system for Cross-Auth. Applications can
now register `before` and `after` callbacks around authentication, session,
OAuth, account-linking, and token issuance flows.

Highlights:

- add typed hook events and a `HookRegistry` for core auth lifecycle events
- expose `auth.before(...)` and `auth.after(...)` on the FastAPI `CrossAuth`
  integration
- support hooks for password authentication, session login/logout, OAuth
  authorize/callback/link/finalize-link, and token password/authorization-code
  grants
- allow `before` hooks to block flows with `CrossAuthException` or replace event
  data with updated dataclass instances
- use framework-neutral `cross_web` request and response objects in hook event
  payloads
- add documentation and examples for choosing the right hook and implementing
  common policy, audit, metrics, and provisioning logic
- add CI type checking with `ty`
