# Review Guide: Completions Architecture

Orientation for reviewing the completion-based refactor. Start here; branch out
via links.

## Read in this order

1. [`completions-architecture.md`](./completions-architecture.md) — the
   canonical design
2. [`refactor-recap.md`](./refactor-recap.md) — what changed and why
3. `src/cross_auth/_completion.py` — the interface everything hangs off
4. `src/cross_auth/_provider_service.py` — the 4 shared helpers
5. `src/cross_auth/completions/session.py` — merged session+attach (simpler of
   the two)
6. `src/cross_auth/completions/token.py` — merged auth-code+link+finalize
7. `src/cross_auth/router.py` — the dispatcher
8. `tests/providers/conftest.py::dispatch_callback` — how completions are
   unit-tested

## What I'd focus on

### The `AuthCompletion` interface shape

Does the 4-method ABC carve up responsibility well?

- `start()` — owns entry-endpoint shape (validation, persistence, redirect)
- `complete()` — owns post-callback response (may raise `OAuth2Exception`)
- `on_failure()` — renders post-callback failures
- `extra_routes()` — contributes auxiliary routes (e.g. `/finalize-link`)

Edge case to probe: `on_failure` takes `flow_state: AuthFlowState` (not
optional). Pre-load callback errors (unknown state, bad JSON) skip `on_failure`
entirely and render generic JSON via the router. Is that the right call?
Arguments for: router can't identify a completion without `kind`. Arguments
against: user in a session-mode app would prefer a redirect-to-login page
instead of raw JSON.

### `completion_state` as an opaque dict

Each completion owns its dict shape — stored via `StartResult` shape in
`AuthFlowState.completion_state`, read back in `complete()`/`on_failure()`. No
schema enforcement at the library level. A typo in a key gets caught at callback
time, not start time. Worth the flexibility, or should there be a Pydantic model
per completion?

### Sub-flow branching inside the two completions

`SessionCompletion.complete` branches on whether `completion_state` carries
`user_id` (set at `start()` when the user was already authenticated):

- `user_id` absent → login path: `exchange_and_resolve_user` + create session
- `user_id` present → attach path: `exchange_and_attach_social_account` against
  the stored user, after verifying the current session user matches

`TokenCompletion.complete` branches on `completion_state["sub_flow"]`:

- `"auth_code"` (from `GET /authorize`) → `exchange_and_resolve_user` + issue
  local auth code
- `"link"` (from `POST /link`) → defer exchange, issue link code; SPA finishes
  with `POST /finalize-link`

The "link flow defers exchange" asymmetry is intentional: the SPA wants to gate
attachment on its own PKCE verifier at finalize time. Watch for leaks in
`_provider_service.py` — `exchange_and_resolve_user` and
`exchange_and_attach_social_account` share provider calls (`exchange_code` +
`get_user_info` + `validate_user_info`).

### Whether I got the URL shape right

`/github/login` / `/github/authorize` / `/github/connect` / `/github/link`.
Intent-named verbs for session-mode, OAuth-vocabulary for SPA-mode. See chat
thread in session for the reasoning (including "authorize" vs "sign-in"
discussion). Keep or push back?

## Invariants to verify

| #   | Invariant                                                                     | Where to check                                                                                                                      |
| --- | ----------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| 1   | Router never calls deleted provider methods                                   | `grep -rn "\.authorize(\|\.callback(\|\.initiate_link(\|\.prepare_link(\|\.finalize_link(\|_link_flow(" src/` should return nothing |
| 2   | Every completion's `start()` persists state only via `prepare_authorization`  | Read each `start()` in `completions/` — none should write `oauth:authorization_request:...` directly                                |
| 3   | Flow state carries `kind` + `provider_id`; every callback verifies both       | `router.py::_make_callback_handler` — checks `flow_state.provider_id != provider.id` before dispatch                                |
| 4   | An attacker can't pick a non-registered kind                                  | Router uses `completion_map.get(flow_state.kind)`; missing → 400                                                                    |
| 5   | `/authorize` validates PKCE + client_id + redirect_uri + response_type        | `TokenCompletion.start` — 8 validation gates                                                                                        |
| 6   | `/token` validates PKCE match                                                 | `Issuer._authorization_code_grant` — unchanged by this refactor                                                                     |
| 7   | Session-attach verifies the session user hasn't changed during the round-trip | `SessionCompletion.complete` — compares `flow_state.completion_state["user_id"]` to `context.get_user_from_request(request).id`     |
| 8   | `/link` requires authentication                                               | `TokenCompletion._link_start` — calls `context.get_user_from_request(request)` and bails on None                                    |
| 9   | `/finalize-link` verifies user owns the link code                             | `TokenCompletion._finalize_link` — compares `user.id` to `link_data.user_id`                                                        |
| 10  | Provider PKCE verifier stored at state top-level (not completion_state)       | `AuthFlowState.provider_code_verifier` is a dedicated field                                                                         |

## Security surface

Checks I'd run on any OAuth refactor:

- **State CSRF:** state tokens are `secrets.token_hex(16)`. Stored in secondary
  storage keyed by state. Validated on callback. State echoed back through
  provider.
- **PKCE, provider leg:** generated server-side if `provider.supports_pkce`.
  Verifier stored in `AuthFlowState.provider_code_verifier`. Sent on
  `exchange_code`.
- **PKCE, SPA leg (`/authorize` flow):** client sends `code_challenge` on
  `/authorize`, sends `code_verifier` on `/token`. Matched by
  `Issuer._authorization_code_grant`.
- **PKCE, SPA leg (`/link` flow):** client sends `code_challenge` on `/link`,
  sends `code_verifier` on `/finalize-link`. Matched in
  `TokenCompletion._finalize_link`.
- **Redirect URI validation:** `context.is_valid_redirect_uri` against
  `trusted_origins` in `TokenCompletion.start`, `TokenCompletion._link_start`,
  and (for `?next=` URLs) `SessionCompletion._validate_next`.
- **Next URL validation:** relative path starting with `/` (not `//`) OR
  absolute URL with trusted host. Rejected otherwise.
- **Client ID validation:** `context.is_valid_client_id` against
  `allowed_client_ids` config. Enforced in `TokenCompletion.start` and
  `TokenCompletion._link_start`.
- **Session swap defense:** `SessionCompletion.complete` (attach path) re-checks
  the current session user against the one captured at `start()` time.

## Tests to read for behavior examples

- `tests/providers/test_oauth_authorize.py` — `TokenCompletion.start` (auth-code
  sub-flow) validation paths (happy path + 7 error conditions)
- `tests/providers/test_oauth_callback.py` — full callback via
  `dispatch_callback` helper (token errors, user info errors, new user creation,
  existing user, account-not-linked, email-not-verified)
- `tests/providers/test_oauth_link.py` — `TokenCompletion._link_start` (link
  sub-flow entry)
- `tests/providers/test_oauth_callback_link.py` — link callback defers exchange;
  only stores `link_code`
- `tests/providers/test_oauth_finalize_link.py` —
  `TokenCompletion._finalize_link` (PKCE verification, user ownership, email
  mismatch, already-linked account)
- `tests/providers/conftest.py` — the `dispatch_callback` helper (replicates
  router dispatch for a single completion) and the `_deterministic_codes`
  fixture

## What's NOT in this refactor

- Password login is NOT modeled as a completion (intentionally):
  - **Password + token** → `Issuer` (`POST /token?grant_type=password`).
    Unchanged by this refactor.
  - **Password + session** → `CrossAuth.authenticate(email, password)` +
    `CrossAuth.login(user_id, response=...)` helpers. Apps wire their own
    `POST /login` endpoint (see `examples/fastapi/main.py`). The library doesn't
    own the route because password UX is too app-specific to canonicalize.
- Apple POST callback with `form_post` response mode — works transparently via
  `AppleProvider.extract_callback_data` override. Router's `/callback` route
  accepts `GET` and `POST`.
- OIDC — `OIDCProvider` is an `OAuth2Provider` subclass, unchanged. Should "just
  work" once someone wires it into a concrete provider.

## Known gaps

- `OAuth2LinkCodeData`, `InitiateLinkRequest`, `InitiateLinkResponse` still in
  `social_providers/oauth.py` but only used by `TokenCompletion`. Moving them
  into `completions/token.py` would be cleaner
- fastapilabs/cloud consumer not yet migrated (see `refactor-recap.md` for
  scope)
