CHANGELOG
=========

0.13.1 - 2026-04-27
-------------------

This release fixes the OpenAPI schema for disconnecting a specific linked OAuth
account.

The `DELETE /{provider}/social-accounts/{social_account_id}` route now documents
its required `social_account_id` path parameter, so generated clients and API
docs correctly show the account-specific disconnect endpoint.

This release was contributed by [@patrick91](https://github.com/patrick91) in [#35](https://github.com/usecross/cross-auth/pull/35)

0.13.0 - 2026-04-26
-------------------

This release adds support for disconnecting linked OAuth provider accounts.

Applications can now expose `DELETE /{provider}/social-accounts` to disconnect
the current user's provider account when only one account for that provider is
connected, or `DELETE /{provider}/social-accounts/{social_account_id}` to
disconnect a specific linked account.

Cross Auth prevents users from removing their only login method by checking for
a usable password or another login-enabled social account. The new
`oauth.disconnect` hooks let applications block disconnects, revoke provider
tokens, clear caches, or audit successful account removals.

Storage backends can support this flow through new social-account lookup,
listing, and deletion methods on the accounts storage protocol.

This release was contributed by [@patrick91](https://github.com/patrick91) in [#34](https://github.com/usecross/cross-auth/pull/34)

0.12.0 - 2026-04-24
-------------------

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

This release was contributed by [@patrick91](https://github.com/patrick91) in [#28](https://github.com/usecross/cross-auth/pull/28)

0.11.0 - 2026-04-24
-------------------

This release adds provider-level hooks for advanced OAuth flows. Providers now
receive the incoming request when building authorization URLs, can intercept
callbacks before the standard OAuth handler runs, and can post-process final
redirect responses.

This release was contributed by [@patrick91](https://github.com/patrick91) in [#32](https://github.com/usecross/cross-auth/pull/32)

0.10.0 - 2026-04-23
-------------------

This release adds session-based social login support to `CrossAuth` and the
FastAPI integration.

Highlights:

- add a browser-session OAuth flow so social login can complete directly into a
  session cookie
- expand the FastAPI example app to demonstrate password login, social login,
  session account linking, and the separate SPA auth-code flow together
- add end-to-end coverage for the FastAPI + SPA example setup

This release was contributed by [@patrick91](https://github.com/patrick91) in [#30](https://github.com/usecross/cross-auth/pull/30)

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