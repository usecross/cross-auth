CHANGELOG
=========

0.9.1 - 2026-03-26
------------------

This release improves error logging in the OAuth2 flow to aid debugging
authentication failures.

- `get_user_info` now logs the endpoint URL, HTTP status code, response body,
  and granted token scope when the provider API returns an error.
- `exchange_code` now logs the token type, granted scope, and expiry after a
  successful token exchange (at DEBUG level).
- GitHub provider's email fetch logs the same details on failure.

This release was contributed by [@patrick91](https://github.com/patrick91) in [#27](https://github.com/usecross/cross-auth/pull/27)

0.9.0 - 2026-03-17
------------------

This release exposes a `prepare_link` method on `OAuth2Provider` which allows to
create custom versions of `initiate_link`

This release was contributed by [@patrick91](https://github.com/patrick91) in [#26](https://github.com/usecross/cross-auth/pull/26)

0.8.0 - 2026-02-22
------------------

This release adds Apple Sign In support via a new OIDC base provider.

Key changes:

- Added `OIDCProvider` base class for OpenID Connect providers, with JWT
  id_token validation against provider JWKS endpoints and automatic key rotation
  handling.
- Added `AppleProvider` for Apple Sign In, supporting ES256 JWT client secret
  generation, `form_post` response mode, and Apple-specific id_token parsing.
- `AppleProvider` now accepts individual constructor args (`client_id`,
  `team_id`, `key_id`, `private_key`) instead of a config object, matching the
  pattern used by other providers.
- Made `client_secret` optional in `OAuth2Provider` for providers like Apple
  that generate it dynamically.
- Renamed `fetch_user_info`/`get_user_info_from_token_response` to
  `get_user_info` for consistency across providers.

This release was contributed by [@patrick91](https://github.com/patrick91) in [#25](https://github.com/usecross/cross-auth/pull/25)

0.7.0 - 2026-02-17
------------------

This release updates the FastAPI session API so `CrossAuth.login()` and
`CrossAuth.logout()` set cookies directly on a provided `Response` rather than
returning cookie objects. Tests and docs were updated to reflect the new usage.

This release was contributed by [@patrick91](https://github.com/patrick91) in [#24](https://github.com/usecross/cross-auth/pull/24)

0.6.0 - 2026-02-16
------------------

This release adds session support via the FastAPI `CrossAuth` class
(`cross_auth.fastapi.CrossAuth`) with high-level `login()` and `logout()`
methods for session management.

- `CrossAuth` class with `authenticate()`, `login()`, `logout()`,
  `get_current_user()`, and `require_current_user()` public methods
- `login(user_id, response=...)` creates a session and sets the cookie on the response
- `logout(request, response=...)` deletes the session and clears the cookie on the response
- `get_current_user()` as a FastAPI dependency with optional `raise_on_missing`
- Server-side session expiry via `expires_at`, enforced on read
- Constant-time password comparison to prevent timing attacks
- `SessionData`, `SessionConfig`, `AccountsStorage`, and `SecondaryStorage`
  exported from `cross_auth`

This release was contributed by [@patrick91](https://github.com/patrick91) in [#21](https://github.com/usecross/cross-auth/pull/21)

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