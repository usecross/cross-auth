# Untangling decision log

## Scope and baseline

The user selected structural refactoring **and** comment/test cleanup. Preserve
public APIs, persisted OAuth formats, security checks, hook ordering and commit
semantics. Existing untracked `IMPLEMENTATION_PLAN.md`, `REVIEW.md`, and
`ROADMAP.md` are not part of this work.

Read-only audit: core orchestration, providers, both ORM adapters, framework
integrations, examples, browser suites, website and tooling. Three independent
reviewers cover core, storage/Django, and providers/tooling. Import inspection
and the last 40 commits identify `_auth_flow.py`, `fastapi.py`, `_login.py`,
`_context.py`, and SQLModel storage as the high-leverage change clusters.

Baseline: `uv run --package cross-auth pytest`: **1563 passed, 7 skipped**;
`uv run --package cross-auth ty check . --exclude website`: passed. The cached
Python 3.11 nox environment is stale (Django missing); synchronize it before
using it for final matrix validation. Skips are schema/user-model applicability,
not disabled regressions.

## Decisions (recorded before implementation)

### 1. Put account identity operations below browser/native orchestration

- Hidden/needless link: `_native.py:14` imports account resolution from the
  2,157-line browser coordinator; `fastapi.py:24` imports its commit guard.
- Hidden link: `_auth_flow.py:1126–1696` owns account creation/update, identity
  hook invariants, credential preservation, user resolution, and attachment.
  Native and browser workflows must use the same policy.
- Hidden link: connect (`1616–1673`) and finalize-link (`2094–2140`) repeat
  owner-scoped create/update/promotion and expansion of token fields.
- Surplus/special case: `_native.py:22–33` invents `_NoTokenResponse`, passed
  through `token_response: Any` merely to express no credential update.
- Fix: extract typed identity/account operations and result types; represent
  absent native credentials explicitly; centralize attachment and hook guards.
  Keep browser-specific validation/response logic in the browser coordinator.
  Preserve import compatibility where existing integrations use old locations.

### 2. Give authorization attempts and codes a single owner

- Hidden link: session, connect, token, and link starters independently generate
  state, provider PKCE, provider data/nonce, browser binding, expiry,
  persistence and authorization URLs (`_auth_flow.py:394–649,1874–1933`).
- Hidden link: code namespace/TTL/model are split between browser code producer
  (`1743–1819`) and `_issuer.py:103–120,205–210` consumer.
- Special convention: callback URL construction assumes a sibling `callback`
  endpoint; centralize rather than duplicate that routing assumption.
- Fix: one attempt builder owns common security setup; endpoint-specific typed
  data, validation, login hints, hooks and response shapes remain explicit. One
  authorization-code module owns its schema, key and expiry policy. Keep
  persisted names and model attributes compatible; do not build a generic
  flag-driven flow engine.

### 3. Carry credential durability with the issued result

- Hidden link: `Context.issue_token` chooses a credential owner, but
  `_on_token_commit` chooses it again later from mutable configuration.
- Hidden link: callback completion repeats its large after-event payload and
  independently rediscovers whether login/session/secondary storage committed.
- Copies: both `_issuer.py` grant handlers construct the same bearer response,
  cache-prevention headers, and completion scheduling.
- Fix: return an internal issuance result with its actual commit scheduler;
  retain the existing tuple-returning convenience API. Centralize the token
  success envelope and callback after-event construction. Do not change
  grant-specific authentication or before-hook payloads.

### 4. Centralize session credential selection and response effects

- Hidden link: logout duplicates cookie-first/bearer-fallback selection but
  intentionally must not slide a session about to be revoked.
- Hidden link: session route success/error branches each remember cookie
  rolling; facade normal/custom resolver paths separately resolve and queue
  cookies.
- Copies: FastAPI cookie translation is repeated in response mutation and ASGI
  serialization. Two loosely related request-state slots implement one sink.
- Surplus: `CrossAuth._add_cookie_to_hook_response` has no callers.
- Fix: shared resolution with an explicit refresh policy, one
  response-finalizing session-route boundary, one facade resolution/queue path,
  and an encapsulated cookie sink/serializer. Preserve explicit response cookies
  over queued rolls.
- Needless link: `_context.py` and `_auth_flow.py` import general header lookup
  from session internals. Move HTTP header handling to the request boundary.

### 5. Remove only demonstrated surplus and implementation-pinning tests (last)

- `tests/test_examples.py` scans `examples/*.py`, but all examples now live in
  subdirectories: the test executes zero examples and always passes.
- `tests/test_hook_registry.py` repeats the exact expression that constructs
  `_ALL_EVENT_NAMES` and checks private defaultdict representation.
- `tests/router/test_user_resolution.py` pins exact lookup counts rather than
  the normalized sign-in result and absence of duplicate records.
- Core/FastAPI issuer suites repeat the full malformed-field matrix; keep core
  validation coverage and framework-specific transport/error coverage.
- `_auth_flow.py` catches `JSONDecodeError` around Pydantic JSON validation,
  which reports `ValidationError`; stored S256 Literal models make later
  discriminator branches unreachable.
- Remove implementation-restating/historical comments, not contract docstrings,
  compatibility notes or explanations of external framework/database behavior.

### 6. Align provider state and error handling with their real ownership

- Hidden link: Google custom JWKS endpoints still share `google:jwks`; emulator
  integrations must override a second unrelated cache-key setting.
- Hidden link/special case: shared JWKS data has per-instance cooldown state;
  rotation deletes working keys before a replacement fetch succeeds.
- Fix: endpoint-aware cache identity, cache-owned refresh timing and successful
  replacement before discarding usable keys. Cover rotation, cooldown, multiple
  provider instances/endpoints and upstream failure; no exchange retries.
- Hidden link: user-info/email/Apple error logging still includes upstream
  bodies/profile data although token errors have a redaction contract. Use the
  same provider/status/category policy at these boundaries.
- Copies: Apple's token-exchange parameter construction duplicates the base
  implementation just to supply its generated client secret. Reuse the base
  construction while preserving actual Apple protocol differences.

### 7. Make examples demonstrate the contracts they depend on

- Hidden link: `examples/fastapi/main.py:92–115` implements atomic `pop` as
  separate `get`/`pop` operations despite concurrent synchronous endpoints. Own
  expiry/removal in one thread-safe storage boundary; test single-consumer
  behavior. Keep SQLite connection serialization separately.
- Copies: the example redeclares unchanged fields/properties of shared SQLModel
  bases (`120–164`). Inherit these; retain application IDs/FKs, relationships,
  constraints and intentionally stricter fields.
- Misleading comments/config descriptions: cookie configuration, sync request
  preloading and SQLModel storage comments describe previous implementations.
  Correct contracts, remove narrative comments.

### 8. Make browser tests own their users, provider and completion signals

- Hidden link: legacy suites share one app/database and a mutable public GitHub
  mock (`e2e/playwright.config.js`); parallel tests mutate `demo@example.com`.
  `CONNECT_DEMO_EMAIL` is an application special case for this test coupling.
- Brittle tests: a five-row session page assumes no concurrent logins; link and
  connect accept any prior provider row; revocation does not prove the original
  credential lost access. SPA stale-response assertions sleep 100ms after mock
  fulfillment, not after response handling.
- Fix: owned local provider/processes and isolated worker/scenario state using
  existing framework-suite patterns; assert specific identities, capabilities,
  storage effects and rejected revoked credentials. Replace arbitrary sleeps
  with observable completion. Keep SPA/session/browser-binding coverage.
- Hidden link: framework emulator callback/identity seed limits (`8` workers,
  `3` repeats) are detached from resolved Playwright configuration. Derive the
  seed plan from that configuration rather than adding test-specific limits.

### 9. Keep provider documentation and website build inputs authoritative

- Hidden link: provider pages duplicate generic login setup but still use
  `/authorize` without required OAuth server/client registration; Google/GitHub
  field promises differ from actual mappings. Link to one flow setup recipe and
  keep provider pages focused on provider-specific configuration.
- Surplus: `website/tailwind.config.js` is unreferenced by Tailwind 4 CSS/Vite.
  Confirm with a website build, then remove the inactive duplicate theme.
- Hidden link: website deployment resolves root workspace dependencies but only
  watches website paths; Bun install is not frozen/pinned. Validate PR website
  builds from explicit root/website inputs and keep production main/manual-only.

### 10. Give environment setup and workflow triggers one owner

- Copies: four nox sessions repeat identical dev-environment synchronization.
  Extract one helper; do not create a generalized workflow framework.
- Surplus: typecheck CI creates an outer environment then nox creates another;
  choose one setup owner. Preserve all supported Python/database/user variants.
- Dead branches: AutoPub scripts test `pull_request` despite only
  `pull_request_target`/`push` triggers. Remove trigger-impossible branches and
  debug-only steps; let artifact upload enforce required files directly.
- Test cleanup (last): synchronous provider tests marked async, Apple scope
  assertions repeated in a separate test, and Route annotation introspection
  already covered by real requests/OpenAPI. Retain behavioral/threadpool checks.

### 11. Make database participation part of storage's atomicity contract

- Hidden link: SQLModel guards against preexisting transactions but can route
  user/identity models to different engines, which cannot commit atomically.
- Hidden link: Django repeatedly chooses a write alias but its user factory has
  no explicit database contract; session listing uses default read routing while
  revocation and notifications use write routing.
- Fix: reject non-atomic SQLModel signup bindings before writing; capture and
  consistently use the authoritative Django alias, document/validate factory
  co-location. Preserve Django outer-transaction callbacks and SQLModel-owned
  fresh transactions rather than inventing a cross-ORM unit-of-work framework.

### 12. Let SQLModel bases define the supported model surface

- Copies: shared bases, required-model string tuples, credential sets, datetime
  tuples and write dictionaries describe the same fields independently.
- Special case: generic datetime preparation writes read-only credential
  properties, although these are explicitly supported; a naive property-backed
  expiry reproduces an AttributeError.
- Fix: base-first validation focused on genuinely application-owned/mapped
  capabilities, typed record normalization, and an explicit property timestamp
  contract. Preserve concrete return types, direct attributes/`col`, property
  email verification, credential-less models and dynamic hook extra-fields.
- Surplus/compatibility: standalone `create_user` and `_build_user` predate
  atomic signup. Make public `build_user`/atomic signup authoritative; retain
  legacy behavior as a documented compatibility seam, not a second design.

### 13. Separate transient-value consumption from garbage collection

- Hidden link: Django `set` deletes every expired row for an unrelated write.
- Hidden link: Django `pop` composes read + conditional delete and is not
  linearizable when another writer overwrites the value between them.
- Fix: one database-owned atomic consume operation; logical expiry on reads and
  explicit or bounded maintenance, not an unbounded cleanup on every OAuth
  write. Redis GETDEL and example locking remain backend-specific
  implementations of the same actual contract.

### 14. Define cursor bounds together with supported identifiers

- Hidden link: encoder accepts arbitrary string IDs but decoder caps output at
  512 characters; a valid 320-character ID generates an undecodable cursor.
- Fix: one explicit supported payload bound enforced symmetrically on output and
  input, with Unicode/boundary roundtrips. Keep defensive size/depth/type
  checks, UUID tagging, order binding, deterministic ties and database ID
  coercion.

### 15. Separate Django session state from management policy and test support

- Hidden link: engine state transitions, management liveness/routing and signal
  delivery share one module; listing duplicates revocation's liveness policy.
- Needless link: runtime imports a backend constant from check registration;
  views repeats the same string. Put backend identity at the integration
  boundary.
- Fix: group management queries/notifications behind a consistent authoritative
  boundary; keep Django engine row/key/login state together and public imports
  compatible. Do not pretend Django sessions and core token sessions are alike.
- Test links: fixtures/helpers imported from test modules trigger PostgreSQL
  `importorskip` during SQLite collection; Django session tests import view-test
  helpers. Move shared support to explicit support/conftest modules; load
  optional database dependencies in the fixture that uses them.
- Test cleanup last: replace unsupported-model diagnostic-order assertions,
  truthiness-only runtime protocol assertions, duplicated codec cases and
  private-wrapper/sleep race coordination with supported-model behavior, static
  typing checks and controlled interleavings. Keep unique backend regressions.

## Necessary special cases to retain

- SameSite=Lax browser binding needs the opaque form-post-to-GET continuation.
  Do not put provider credentials/profile data into redirect URLs.
- Validate browser, provider and linking user before consuming authorization
  state. Wrong-user/browser/verifier requests must not consume valid attempts.
- Token codes consume before validation; link codes validate before atomic pop.
  Link expiry is checked again after extension code/consumption deliberately.
- Session and connect callbacks remain available without an OAuth server;
  pending token/link attempts must still be refused after server disablement.
- Connect only applies login email policy when enabling login; finalize-link
  applies its existing policy regardless. Connections never implicitly grant
  login. Native sign-in preserves existing provider credentials.
- Before-hook failure issues nothing; after-hook failure leaves durable data and
  stops later hooks. Cookie response effects require immediate commits; bearer
  issuance supports deferred commit. Snapshots and immutable identity guards
  remain necessary despite frozen outer event dataclasses.
- Cookie credentials take precedence; invalid cookies may fall back to bearer,
  but a valid session whose user was removed does not. Logout never refreshes.
  Zero revocations have no after hook. Session routes authenticate the actual
  session, not an application's custom user resolver.
- Disabled password grant is refused before validation/account lookup; its
  opt-in compatibility/deprecation behavior stays until advertised removal.
- PostgreSQL/SQLite timezone binding, ID coercion, locking and race recovery
  express actual backend differences, not incidental special cases to erase.

## Implementation and verification

All 15 grouped decisions are implemented. The inventory and redesign above were
recorded before editing; implementation was followed by independent review,
concrete follow-up fixes, and final validation before preparing the PR.

### Resulting ownership

- `_accounts.py` owns account resolution, creation, attachment, immutable hook
  identity guards, credential preservation, and account durability checks.
  Browser and native orchestration both depend on it.
- `_authorization.py` owns persisted attempts, common state/PKCE/provider setup,
  binding, expiry and callback construction. `_authorization_code.py` owns the
  code schema/key/TTL shared by producer and consumer. Existing imports remain
  compatible through aliases rather than parallel implementations.
- Token issuance and callback completion carry the selected credential owner's
  commit scheduler. Configuration changes inside storage, custom issuers or
  after-login hooks cannot silently transfer completion ownership.
- `_session.py` owns credential selection; logout disables refresh explicitly.
  `_session_routes.py` finalizes response effects once; `_fastapi_session.py`
  owns cookie serialization, queuing and middleware. General header lookup is at
  `_request.py`, not coupled to session internals.
- SQLModel owns supported model boundaries, same-bind signup validation and
  property-aware datetime handling. Cursor encoding and decoding share one
  4096-character bound. Legacy builders remain compatibility seams.
- Django owns one captured authoritative database alias, validated/co-located
  user factories, atomic transient-value consumption and explicit expiry
  maintenance. `_session_management.py` separates management policy from engine
  state while preserving public imports. Shared test support no longer imports
  other test modules or forces optional PostgreSQL dependencies on SQLite.
- JWKS endpoint identity, cache state and completed refresh cooldowns agree.
  Failed refreshes preserve usable keys; profile/token errors are redacted.
  Apple reuses base exchange construction while retaining its actual protocol.
- Examples use atomic secondary storage and shared model fields. Browser
  scenarios own local providers, processes, users and databases; resolved
  Playwright configuration owns callback port blocks and repeat-index seeding.
  SPA response completion is an accessible named region's `aria-busy` state, not
  a sleep or visible test-only counter.
- Documentation describes the actual flow setup, field mappings and storage
  contracts. Website builds have pinned/frozen inputs and PR coverage; inactive
  theme configuration is removed. Nox synchronization and CI environment setup
  have one owner without dropping supported variants.

### Comments and tests, after structural changes

Removed implementation narration, dead branches, the vacuous example-file scan,
private container/annotation assertions, lookup-count pinning and duplicated
framework issuer-validation cases. Kept unique transport, threading, security,
backend and external-contract explanations and regressions. Replacement tests
assert normalized identities, unchanged credentials, durable completion,
transactional participation, atomic consumption, cache concurrency, exact
browser identities/capabilities, and rejected revoked bearer credentials.

### Independent review and follow-ups

Core, storage/Django, and browser/tooling reviewers checked the combined work.
Storage/Django reported no worthwhile residual findings. Core identified a
remaining duplicated framework issuer matrix; it was trimmed while retaining
representative form transport checks and the authoritative core matrix. The
reviewer independently reran the affected completion/issuer tests: **59
passed**, and verified captured scheduler ownership and its regression.

Browser/tooling review identified stale global-setup documentation and redundant
per-framework base ports. Scenario-owned documentation and one allocation base
resolved both. A further pass replaced the SPA's visible pending-request debug
UI with accessible busy/idle semantics; both affected stale-response tests pass.
The reviewer checked those changes and reported no worthwhile remaining issue.
Final wording now describes scenario-local seeding and the actual region signal.

Validation also exposed JWKS cold-cache races introduced by the cache redesign.
Cooldown markers now describe completed fetches rather than in-flight requests;
readers recheck newly published cache data. Four deterministic regressions cover
cold and warm concurrent consumers and failed refreshes. They reproduce the
rejected-concurrent-login behavior before the correction and pass afterward.

A final import inspection covers 63 package modules and finds no import-time
cycles after excluding type-only and deferred function imports. Deferred Django
model/session-store lookups and the public session-management reexports remain
necessary framework/compatibility seams, not new initialization requirements.
All three independent review tracks ended with no worthwhile unresolved finding.

### Refactor verification before the post-PR follow-up

| Check                                                                           | Result                          |
| ------------------------------------------------------------------------------- | ------------------------------- |
| `uv run --frozen --package cross-auth nox -t tests`                             | All eight sessions pass         |
| Python 3.11, 3.12, 3.13 and 3.14 full suites                                    | **1620 passed, 7 skipped** each |
| Django on Python 3.14 / SQLite / default user                                   | **247 passed, 1 skipped**       |
| Django on Python 3.14 / SQLite / custom user                                    | **246 passed, 2 skipped**       |
| Django on Python 3.14 / PostgreSQL / default user                               | **247 passed, 1 skipped**       |
| Django on Python 3.14 / PostgreSQL / custom user                                | **246 passed, 2 skipped**       |
| `nox -s typecheck-3.14` (`ty check . --exclude website`)                        | Passed                          |
| Framework browser stress: 9 workers, 4 repeats                                  | **64 passed**                   |
| Legacy browser stress: 4 workers, 2 repeats                                     | **28 passed**                   |
| Final SPA stale-response checks after accessibility change                      | **2 passed**                    |
| E2E TypeScript typecheck                                                        | Passed                          |
| Pinned Bun 1.3.11 frozen website production build and rendered-doc smoke checks | Passed                          |
| Combined validation coverage                                                    | **97%**, above the 80% gate     |

The seven full-suite skips and the user-model-specific Django skips are
intentional schema applicability, not disabled regressions. Existing dependency
warnings and the website's large-chunk warning remain non-blocking. Changed-file
hooks (including formatting, lint and root typing) and `git diff --check` pass
after applying the hooks' automatic formatting.

### Post-PR review: explicit Django user-creation database

The initial implementation preserved the existing `CREATE_USER` signature by
passing the captured alias through a context variable and
`conf.user_database()`. Review identified this as unnecessary ambient coupling.
The user confirmed that the Django integration has no external compatibility
requirement for this API.

Replace that mechanism with a required `using: str` keyword on the user-creation
protocol and default/custom functions. Storage passes its captured alias
directly; functions use it for user and related-row writes. Remove
`_database.py` entirely, without signature detection or a legacy fallback.
Extend the multi-database regressions to cover both custom creation paths after
routing changes and rollback of user, profile and identity rows on the
explicitly supplied database.

Implemented and independently reviewed with no worthwhile residual findings.
Follow-up validation: full Python 3.13 suite **1622 passed, 7 skipped**; all
four Python 3.14 Django variants pass (**249 passed, 1 skipped** for the default
user, **248 passed, 2 skipped** for the custom user, on both SQLite and
PostgreSQL). Root `ty check . --exclude website`, rendered Django-doc smoke
checks and changed-file hooks pass.

### Deliberately retained limits and compatibility

- The security/backend exceptions listed above remain requirements, not
  opportunities to unify different protocols or transaction models.
- `SecondaryStorage` provides `get/set/pop`, not CAS or distributed
  single-flight. Simultaneous distributed JWKS misses can issue redundant
  network requests; they must not reject otherwise-valid concurrent logins. No
  speculative new distributed coordination API was introduced.
- Django custom factories must keep all related writes on the supplied `using`
  alias; returned-user validation cannot inspect arbitrary side-effect writes.
  SQLModel custom builders must honor the documented no-flush/same-bind
  contract.
- Expired Django transient rows are logically absent immediately; deployments
  schedule `DjangoSecondaryStorage.clear_expired()` for physical cleanup.
- The original untracked planning/review/roadmap documents remain untouched.
