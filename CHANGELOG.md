CHANGELOG
=========

0.5.0 - 2026-01-12
------------------

Added `POST /{provider}/link` endpoint for initiating account link flows.

This is the recommended way to start linking a social account. It accepts a JSON body with the OAuth parameters and returns the provider's authorization URL. Authentication happens via the standard `Authorization` header, so tokens never appear in URLs.

### Usage

```javascript
// POST /api/v1/github/link
const response = await fetch("/api/v1/github/link", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    Authorization: `Bearer ${accessToken}`,
  },
  body: JSON.stringify({
    redirect_uri: "https://example.com/callback",
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
    client_id: "my_app",
  }),
})

const { authorization_url } = await response.json()
window.location.href = authorization_url
```

### Breaking Change

The `response_type=link_code` parameter on the `GET /{provider}/authorize` endpoint is no longer supported. Use the new `POST /{provider}/link` endpoint instead.

0.4.0 - 2026-01-12
------------------

This release adds support for `client_id` validation, which is now required when calling `/authorize`.

**Before:**
```
GET /github/authorize?redirect_uri=...&response_type=code&code_challenge=...&code_challenge_method=S256
```

**After:**
```
GET /github/authorize?client_id=my_app&redirect_uri=...&response_type=code&code_challenge=...&code_challenge_method=S256
```

The same `client_id` must be sent in the token exchange request.

0.3.0 - 2026-01-02
------------------

Add secure account linking for social authentication providers.

**New features:**

- Configurable `account_linking` settings:
  - `enabled`: Enable/disable account linking (required for both manual and automatic linking)
  - `allow_different_emails`: Allow linking accounts with different emails
- Manual account linking via `response_type=link_code` flow
- Automatic account linking by email during login

**Security improvements:**

- Fail fast at authorize time if linking is disabled (better UX)
- Email verification checks for untrusted providers
- Link codes are bound to the user who initiated the flow

0.2.0 - 2025-12-23
------------------

Add `id_token` field to `TokenResponse` for OpenID Connect support. This optional field holds the ID token returned alongside the access token in OIDC flows.

0.1.3 - 2025-12-23
------------------

This release adds missing `__init__.py` files

0.1.2 - 2025-12-23
------------------

# GitHub provider: fallback to username when name is not set

Some GitHub users don't have a display name configured on their profile. Previously, this would result in `name` being `null` in the user info. Now, we fall back to using the GitHub username (`login`) when `name` is not set, ensuring users always have a display name.

0.1.1 - 2025-11-24
------------------

Initial release