---
release type: minor
---

OIDC validation now requires issuer, subject, audience, expiry, and issued-at
claims. Missing or malformed claims and malformed JWT headers fail with
`invalid_token`. Native sign-in nonce checks reject empty and malformed values
without unexpected comparison errors, while retaining raw and SHA-256 matching.

Browser OIDC flows now generate, retain, and validate a nonce for each login,
connection, or link attempt. Static nonce extras cannot override it. Pending
OIDC attempts started before the upgrade must restart. Custom
`build_authorization_url`, `build_authorization_params`, and `fetch_user_info`
overrides must accept and forward the optional `provider_data` keyword.
Providers can generate per-attempt data with `get_authorization_data()`;
Cross-Auth retains it through callbacks and link redemption. Native `nonce=`
remains available; applications own native challenge binding and single-use
consumption.

The minimum PyJWT version is now 2.10.1, which fixes partial issuer matching and
supports the issuer lists used by Google.
