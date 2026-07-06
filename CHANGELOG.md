CHANGELOG
=========

0.20.1 - 2026-07-06
-------------------

A token-less sign-in — `sign_in_with_id_token`, where no OAuth code exchange
happens — no longer overwrites provider credentials stored on the social account
by an earlier web flow. Previously a repeat sign-in through the native path
nulled the stored access/refresh tokens and scope, silently breaking apps that
call the provider's API later (e.g. a Google refresh token used for background
calendar sync). Identity fields (`provider_email`, `provider_email_verified`,
user info) still refresh from the new token's claims; a web code exchange, which
always carries an access token, updates credentials exactly as before.

The `SocialAccount` protocol now declares the credential fields (`access_token`,
`refresh_token`, their expiries, and `scope`) as read-only properties. Storages
were already required to accept them as
`update_social_account`/`create_social_account` keyword arguments; declaring
them readable is what lets core preserve stored values, and models built for the
documented adapters already expose them.

This release was contributed by [@patrick91](https://github.com/patrick91) in [#51](https://github.com/usecross/cross-auth/pull/51)

0.20.0 - 2026-07-06
-------------------

New
`CrossAuth.sign_in_with_id_token(provider, id_token, *, user_info=None, nonce=None)`
signs in native/SDK logins — Apple's ASAuthorization, Google's Credential
Manager — by validating the provider id_token against its JWKS and then finding
or creating the user through the same core the web OAuth callback uses:
normalized email lookup, the account-linking policy gate, and the
accounts-storage signup hooks. Apps no longer need to hand-roll the
find-or-create around `validate_id_token` (and silently skip email normalization
and the auto-link safety gate while doing so). `user_info` overlays the token
claims for data providers deliver outside the token, such as Apple's
first-authorization name; `nonce`, when given, must match the token's nonce
claim raw or SHA-256 hashed. Returns `(user, created)`; pair it with
`issue_session_token` for a bearer token. The new `oauth.id_token` before/after
hooks run around the flow, and only `OIDCProvider` subclasses support it —
providers without id_tokens (e.g. GitHub) raise a clear error.

This release was contributed by [@patrick91](https://github.com/patrick91) in [#50](https://github.com/usecross/cross-auth/pull/50)

0.19.0 - 2026-07-05
-------------------

New `CrossAuth.issue_session_token(user_id, *, max_age=None, metadata=None)`
mints a revocable opaque bearer token programmatically — for clients that
authenticate outside the built-in `/token` endpoint and outside a browser, such
as a GraphQL sign-in mutation for a native app or a CLI. It returns the raw
token together with the created session record, honors a per-call `max_age`
(e.g. longer-lived mobile sessions than browser cookies), stores the usual
session metadata, and the token resolves through `get_current_user` and revokes
through the existing session-management APIs. No cookie is set, and the new
`session.issue` before/after hooks run around the creation — so programmatic
issuance goes through the same policy and audit surface as cookie logins and
`/token` grants (block suspended users, clamp requested lifetimes, audit issued
sessions). The raw token is never exposed to hooks.

This release was contributed by [@patrick91](https://github.com/patrick91) in [#49](https://github.com/usecross/cross-auth/pull/49)

0.18.0 - 2026-07-05
-------------------

`get_current_user`, `require_current_user`, and `get_current_session` now take
only the request, so one API serves FastAPI dependencies and direct calls
(shared-context builders, GraphQL resolvers, template helpers) alike. Rolling
the sliding-session cookie moved out of the read path into the new
`SessionCookieMiddleware`: reads that refresh a session queue the rolled cookie
on the request state, and the middleware delivers it on whatever response the
handler produces — including responses returned directly (redirects, streaming,
server-rendered pages), which the previous dependency-injected `Response`
mechanism silently could not reach. If a session refreshes without the
middleware installed, Cross-Auth warns instead of letting the browser cookie
lapse silently.

**Upgrade note:** drop the `response` argument from `get_current_user`,
`require_current_user`, and `get_current_session` calls, and if you configure
`update_age`, add `app.add_middleware(SessionCookieMiddleware)`. `login()` and
`logout()` are unchanged. Without `update_age` the middleware is unnecessary.

The storage record protocols (`SocialAccount`, `User`, `SessionRecord`) now
declare their data members as read-only properties, so concrete models satisfy
them structurally under precise type checkers like `ty`: attributes were checked
invariantly, which rejected models that narrow a field (e.g. a non-nullable
`provider_email_verified`) — including the built-in SQLModel adapters
themselves. Core only ever reads these members, so nothing changes at runtime.
`User.email` is now typed `str | None` to match reality (apps may hold users
without an email; core never reads it — lookups go through
`find_user_by_email`), and the `SocialAccount` protocol is now exported from
`cross_auth`.

This release was contributed by [@patrick91](https://github.com/patrick91) in [#48](https://github.com/usecross/cross-auth/pull/48)

0.17.0 - 2026-07-03
-------------------

This release adds built-in storage adapters, normalizes emails across every
lookup and signup, and hardens transient OAuth state so abandoned flows don't
linger and callbacks can't be replayed.

- **Built-in storage adapters**: `SQLModelSessionStorage` and
  `SQLModelAccountsStorage` (`cross-auth[sqlmodel]`) implement the session and
  accounts storage protocols on your own SQLModel models, with signup hooks
  (`build_user`, `on_signup`, `after_signup`), query filters, keyset cursor
  pagination that raises `InvalidCursorError` for bad cursors, and model
  validation at construction. `RedisStorage` (`cross-auth[redis]`) implements
  `SecondaryStorage` on a synchronous redis-py client.
- Emails are now trimmed and lowercased before every user lookup and creation —
  password login, the token endpoint, OAuth signup, and account linking all go
  through it. Pass `normalize_email=` to `CrossAuth` to customize the
  normalization.
- Transient OAuth state (authorization requests, auth codes, link codes) is now
  stored with a 10-minute TTL, so abandoned flows no longer accumulate in
  storage. The authorization-request state is also single-use: it's consumed on
  the callback, so a replayed callback is rejected instead of staying valid
  until the TTL expires.
- New public helpers: `session_status`, the canonical active/expired/revoked
  derivation used by the storage adapters, and `normalize_email`.

**Upgrade note:** if you're upgrading from 0.16 or earlier and any stored emails
aren't already lowercase, backfill them before upgrading — e.g.
`UPDATE "user" SET email = lower(trim(email))` — and resolve any duplicate rows
that produces. Skipping this means existing users with non-lowercase stored
emails will fail password login, and OAuth sign-ins can create duplicate
accounts instead of matching the existing one.

This release was contributed by [@patrick91](https://github.com/patrick91) in [#44](https://github.com/usecross/cross-auth/pull/44)

0.16.0 - 2026-05-25
-------------------

This release adds durable session storage support, session management APIs, and
a FastAPI example dashboard for listing and revoking sessions. The built-in
`/token` endpoint now issues revocable opaque session tokens when
`session_storage` is configured. The old `create_token` callback has been
removed; supply a `token_issuer` instead to mint custom tokens (e.g. JWTs).

This release was contributed by [@patrick91](https://github.com/patrick91) in [#42](https://github.com/usecross/cross-auth/pull/42)

0.15.0 - 2026-05-19
-------------------

This release makes auth routes and hooks synchronous, allowing applications that
use synchronous dependencies such as database clients to run auth logic without
blocking the event loop.

It also updates Cross Auth to use `cross-web`'s synchronous `HTTPRequest`
wrapper.

This release was contributed by [@patrick91](https://github.com/patrick91) in [#38](https://github.com/usecross/cross-auth/pull/38)

0.14.1 - 2026-05-18
-------------------

This release lowers the log level for expected OAuth callback errors so they no
longer trigger error-level alerts on routine user actions.

When a user denies consent at the provider (`access_denied`), the OAuth callback
handler now logs at `INFO` instead of `ERROR`. Unexpected provider errors (e.g.
`invalid_request`) continue to be logged at `ERROR`.

This release was contributed by [@patrick91](https://github.com/patrick91) in [#39](https://github.com/usecross/cross-auth/pull/39)

0.14.0 - 2026-05-14
-------------------

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

This release was contributed by [@patrick91](https://github.com/patrick91) in [#37](https://github.com/usecross/cross-auth/pull/37)

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