---
release type: patch
---

Custom OAuth providers can now return `TokenResponse` or `TokenErrorResponse`
directly from `parse_token_response`. The `OAuth2TokenEndpointResponse` wrapper
has been removed; providers overriding this hook should return the contained
success or error model directly. Built-in token exchange behavior and response
formats are unchanged.
