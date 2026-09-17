---
release type: minor
---

Expose `get_bearer_token(request)` for applications that provide their own token
verification. Session resolution uses the same helper. Missing headers,
non-Bearer schemes, and whitespace-only credentials return `None`.
