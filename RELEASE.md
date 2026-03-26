---
release type: patch
---

This release improves error logging in the OAuth2 flow to aid debugging
authentication failures.

- `get_user_info` now logs the endpoint URL, HTTP status code, response body,
  and granted token scope when the provider API returns an error.
- `exchange_code` now logs the token type, granted scope, and expiry after a
  successful token exchange (at DEBUG level).
- GitHub provider's email fetch logs the same details on failure.
