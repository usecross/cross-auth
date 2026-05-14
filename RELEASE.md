---
release type: minor
---

Add a new OAuth provider for Google, with local ID token validation against
Google's JWKS endpoint.

This release also includes a few related improvements to the OAuth2 / OIDC base
classes:

- `OAuth2Provider` now accepts an `extra_authorization_params` keyword argument
  for appending custom query parameters to the authorization URL (e.g. Google's
  `access_type=offline`, `prompt=consent`, `hd`, `include_granted_scopes`).
  Provider-controlled parameters such as `state`, `client_id`, and
  `redirect_uri` cannot be overridden.
- `OIDCProvider.issuer` now accepts either a single string or a list of strings
  to support providers (like Google) that emit ID tokens with multiple valid
  issuer forms.
- OIDC JWKS caching now honors the `Cache-Control: max-age` header from the
  provider's JWKS response (clamped between 5 minutes and 24 hours) instead of
  using a fixed 24-hour TTL, so caches no longer outlive the provider's key
  rotation window.
