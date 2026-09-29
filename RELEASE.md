---
release type: minor
---

Remove unused code and deprecate the `trusted_origins` argument, which has had
no effect since client redirects moved to exact per-client registration.

**Breaking change:** `trusted_origins` is now optional on `CrossAuth` and
`AuthRouter`, and passing it emits a `DeprecationWarning`. Remove it from your
constructor calls before it is removed in a future release; test suites that
turn warnings into errors fail until you do. It never configured CORS or CSRF
protection, so keep configuring those in your application.

**Breaking change:** `Context` no longer accepts `trusted_origins`, and
`Context.create_session_cookie()` has been removed. Call
`Context.create_session()` and pass the returned token to
`make_session_cookie()` instead.

**Breaking change:** the unused `GitHubUser`, `GitHubPlan`, and `DiscordUser`
models have been removed from `cross_auth.social_providers`.

**Breaking change:** the `AccountsStorage` protocol no longer declares
`create_user` or `delete_social_account`, which Cross-Auth never called. Custom
implementations can drop them. `SQLModelAccountsStorage` keeps both methods for
application code.
