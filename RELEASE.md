---
release type: minor
---

This release adds durable session storage support, session management APIs, and
a FastAPI example dashboard for listing and revoking sessions. The built-in
`/token` endpoint now issues revocable opaque session tokens when
`session_storage` is configured. The old `create_token` callback has been
removed; supply a `token_issuer` instead to mint custom tokens (e.g. JWTs).
