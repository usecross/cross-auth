# Refactor Recap: Completions Architecture

Date: 2026-04-16. Branch: `feature/session-oauth`.

## Why

`OAuth2Provider` used to own its HTTP handlers (`authorize`, `callback`,
`prepare_link`, `initiate_link`, `finalize_link`, plus a `.routes` property).
That coupled HTTP routing, state persistence, session cookies, and token
issuance into the provider class, which made "session-mode social login"
impossible to add cleanly — a previous attempt was reverted ("WIP revert"
commit). The URL shape also mixed spec vocabulary with non-spec federation
(`/github/authorize` is half-RFC, half-NextAuth), and adding a new mode would
have meant new routes on every provider × mode pair.

The goal: make transports pluggable, keep providers as pure strategies, and have
one callback URL per provider that dispatches based on the flow being completed.

## What changed

### New

- `src/cross_auth/_completion.py` — `AuthCompletion` ABC, `AuthFlowState`
  (persisted state), `ProviderAuthResult`
- `src/cross_auth/_provider_service.py` — `prepare_authorization`,
  `parse_callback_and_load_state`, `exchange_and_resolve_user`,
  `exchange_and_attach_social_account`, plus small utilities
- `src/cross_auth/completions/` — `session.py` (session + attach), `token.py`
  (auth-code + link + finalize-link)
- `specs/completions-architecture.md` — canonical design doc

### Changed

- `src/cross_auth/router.py` — rewritten to accept `completions=[...]`, register
  entry routes per (completion, provider), register one `/callback` per provider
  that dispatches by `flow_state.kind`, plus `extra_routes()` contributions from
  each completion
- `src/cross_auth/fastapi.py::CrossAuth` — accepts and forwards
  `completions=[...]`
- `src/cross_auth/utils/_url.py::construct_relative_url` — rewritten to parse
  URL properly instead of splitting on `/`. **This was a pre-existing bug**;
  only surfaced now because `SessionCompletion` is the first entry endpoint
  whose URL carries `?next=/profile` with an embedded slash
- `examples/fastapi/main.py` — uses
  `completions=[SessionCompletion(...), TokenCompletion()]`

### Removed

- `OAuth2Provider.authorize`, `callback`, `_link_flow`, `prepare_link`,
  `initiate_link`, `finalize_link`, `.routes` property, `_generate_code`
- `OAuth2AuthorizationRequestData` (replaced by `AuthFlowState`)
- `PreparedLink` dataclass
- `AuthCodeCompletion`, `LinkCompletion`, `ConnectCompletion` (merged into
  `SessionCompletion` + `TokenCompletion` — sub-flow branching via
  `completion_state`)

### Deleted (obsolete specs; preserved in git history)

- `specs/oauth-flow-architecture.md`
- `specs/social-login-browser-session.md`
- `specs/github-session-vs-api-spa.md`
- `specs/auth-flow-map.md`

## Route shape

| Flow                                       | Before                           | After                                                                             |
| ------------------------------------------ | -------------------------------- | --------------------------------------------------------------------------------- |
| SPA auth-code                              | `GET /{provider}/authorize`      | same (owned by `TokenCompletion`)                                                 |
| Session social login (first-party, unauth) | —                                | **`GET /{provider}/login?next=`** (owned by `SessionCompletion`)                  |
| Session account link (first-party, auth)   | —                                | **same URL** `GET /{provider}/login?next=` — branches internally on session state |
| SPA account link                           | `POST /{provider}/link`          | same (owned by `TokenCompletion`)                                                 |
| Link finalize                              | `POST /{provider}/finalize-link` | same (owned by `TokenCompletion`)                                                 |
| Callback                                   | `GET\|POST /{provider}/callback` | same (now dispatches by `flow_state.kind`)                                        |
| Token exchange                             | `POST /token`                    | same                                                                              |

SPA contract is unchanged: all URLs the cloud app's frontend hits (`/authorize`,
`/link`, `/finalize-link`, `/callback`, `/token`) behave identically.

## Tests

- Unit: **168 passing** (was 170 — 2 Apple route-count tests deleted since
  providers no longer own routes)
- E2E (Playwright): **5/5 passing** (`session-connect`, `session-linking`,
  `session-social-login`, `spa-auth`, `spa-linking`)
- New helper `dispatch_callback` in `tests/providers/conftest.py` replicates the
  router's callback pipeline so completion behavior can be tested without
  spinning up a FastAPI app
- New autouse fixture `_deterministic_codes` monkeypatches `uuid.uuid4` for
  snapshot stability (old `TestOAuth2Provider._generate_code` override is gone —
  completions use uuid directly)

## Consumer migration (fastapilabs/cloud)

- **Frontend (`frontend/src/lib/auth.ts`):** zero changes. All hardcoded URLs
  preserved.
- **Backend (`backend/app/api/routes/auth/router.py`):** ~5-line change to pass
  `completions=[TokenCompletion()]`.
- **Custom `GitHubProvider` subclass
  (`backend/app/api/routes/auth/github_provider.py`):** ~80-line rewrite. It
  currently overrides `callback()` and `initiate_link()` which don't exist
  anymore. Those overrides need to move onto `extract_callback_data` (to stuff
  `installation_id` into `CallbackData.extra`) and `build_authorization_url` (to
  swap to GitHub App install URL when `?install=true`). The "append
  installation_id to redirect" logic moves into the completion's final redirect
  handling.
- **Version:** cloud pins `cross-auth>=0.9.0` (locked to `0.9.1`). This refactor
  is a breaking change — bump to `1.0.0`, cloud pins explicitly.

## Known gaps / next up

- Superseded specs kept for historical context; could be deleted later
- `OAuth2LinkCodeData`, `InitiateLinkRequest`, `InitiateLinkResponse` still live
  in `social_providers/oauth.py` but are only used by `LinkCompletion`. Could
  move to `completions/link.py` in a future cleanup
- No `PasswordCompletion` — **on purpose**, not a gap. Password+token login is
  served by `Issuer` (`POST /token?grant_type=password`). Password+session login
  is served by `CrossAuth.authenticate` + `CrossAuth.login` helpers, which apps
  call from their own `POST /login` endpoint (see `examples/fastapi/main.py`).
  The asymmetry with social flows (library-registered routes) is deliberate —
  password UX is too app-specific (error shape, 2FA, captcha, reset flows) to
  want a canonical route shape
