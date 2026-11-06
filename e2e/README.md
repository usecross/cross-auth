# Cross-Auth End-to-End Tests

Playwright tests, written in TypeScript, for the example applications. There are
two suites with separate configs:

- **Shared framework contract** (`playwright.frameworks.config.ts`): one set of
  browser scenarios that runs against every supported framework's example app
  (Django and FastAPI today) with Google served by a local emulator.
- **FastAPI + SPA suite** (`playwright.config.js`): the FastAPI hybrid backend
  and the separate SPA demo, signing in through a scenario-owned local GitHub
  emulator.

## Setup

```bash
cd e2e
bun install
bunx playwright install chromium
```

The Python examples are members of the repository's uv workspace. Install all
workspace dependencies from the repository root:

```bash
uv sync --frozen --all-packages
```

This includes the Django and FastAPI examples and the website. New example
packages added to the workspace are included automatically.

## Shared framework contract

Run every scenario against every framework:

```bash
bun run test:frameworks
```

Run it against one framework:

```bash
bun run test:frameworks --project django
bun run test:frameworks --project fastapi
```

### Files

```text
playwright.frameworks.config.ts   one Playwright project per framework
frameworks/
  frameworks.ts                   the framework list
  contract/*.spec.ts              shared scenarios and every assertion
  support/app.ts                  the App interface used by shared scenarios
  support/browser.ts              shared browser actions and profile/session checks
  support/fixtures.ts             scenario-owned app/provider, network guard, identities
  support/google.ts               emulator seed, test identities, account picker
  support/plan.ts                 ports derived from resolved Playwright config
  support/process.ts              server start, readiness and cleanup
  django/app.ts                   Django startup/state + declarative routes/labels
  django/e2e_settings.py          the example's settings, pointed at the emulator
  django/e2e_support/             test-only Django app with the e2e_state command
  django/*.spec.ts                Django-only behavior
  fastapi/app.ts                  FastAPI startup/state + declarative routes/labels
  fastapi/state.py                seeds password users, reads users/identities
  fastapi/*.spec.ts               FastAPI-only behavior
```

### How it runs

- `support/fixtures.ts` starts a scenario-owned Google emulator from
  [emulate](https://emulate.dev) (pinned in `package.json`) on a free loopback
  port, passing `GOOGLE_EMULATOR_URL` to the owned application process.
- Each scenario starts the real example app (`examples/django` with
  `manage.py runserver`, `examples/fastapi` with uvicorn) on its worker's port,
  with a fresh SQLite database in a temporary directory. Ports start at `8180`,
  with one block per configured project sized by the resolved worker count
  (including `--workers` overrides). The emulator allows exactly those
  callbacks. An already answering port fails the run instead of being reused.
  Servers stop, and databases are removed, when the scenario ends (including
  retries and repeats).
- Server output goes to each scenario's `servers/` directory beneath
  `test-results/frameworks/` and is attached to failures beside Playwright's
  trace.
- Emulator users are seeded before each scenario starts; every Google identity
  is declared in `support/google.ts`. The fixture seeds the actual scenario's
  `testInfo.repeatEachIndex`; unlike global setup or worker project config, this
  reflects CLI `--repeat-each` overrides. Scenarios never share mutable provider
  state, and password users are created per scenario through Django's
  `manage.py e2e_state` command or FastAPI's `state.py` helper.
- Every browser request outside `127.0.0.1` and `localhost` is blocked and fails
  the test. The apps reach the emulator's token and JWKS endpoints over HTTP;
  nothing calls Google.

Test-only configuration stays out of the examples' defaults:

- Django: `django/e2e_settings.py` imports the example's settings, replaces the
  database and Google provider, and installs the test-only `e2e_support` app.
  Its `manage.py e2e_state seed-password-user EMAIL PASSWORD` and
  `manage.py e2e_state facts EMAIL` commands seed users and read account facts.
  Django handles setup, argument parsing and output; the command is unavailable
  with the example's normal settings. Views, templates, signals, middleware and
  Django's own sessions and password login are unchanged, and
  `ALLOWED_EMAIL_DOMAIN=e2e.test` turns on the example's domain policy.
- FastAPI: `examples/fastapi/main.py` reads `EXAMPLE_BASE_URL`,
  `EXAMPLE_DATABASE_URL` and `GOOGLE_EMULATOR_URL`. Unset, the demo is the same
  in-memory GitHub-only app as before.

Both apps subclass `GoogleProvider` only to accept the emulator's issuer (its
own URL). The provider derives JWKS cache identity from its endpoint. Signature,
audience, nonce, PKCE and state checks are the library's normal ones.

### Scenarios

Shared, run for each framework:

- A new Google user is signed up, sees the protected profile, and stays signed
  in after a reload.
- A returning Google user signs in to the same native user, without a second
  user or identity.
- A password user connects Google, keeps their profile, and can then sign in
  with Google as the same user.
- Disconnecting Google keeps the user and password sign-in; Google can be
  connected again.
- Google cannot be disconnected when it is the only way to sign in; the user
  stays signed in and connected.
- An app policy (Django's `before_callback` receiver, FastAPI's
  `before("oauth.callback")` hook) answers 403 to a new identity, leaving no
  session, user or identity.
- An unverified Google email cannot sign up and leaves nothing behind.

Assertions use the app's own pages and the rows in its database (`facts` returns
the users with an email and the Google identities that belong to them or report
it), so a duplicate user or identity fails the scenario.

Framework-specific, run only for that framework:

- Django (`django/csrf.spec.ts`): the provider views are POSTs behind
  `CsrfViewMiddleware`; a request without a token is refused.
- FastAPI (`fastapi/connect-integration.spec.ts`): `GET /auth/google/connect`
  adds an integration-only connection, which sign-in refuses. Django only offers
  login-enabled linking, so the shared "connect" step uses each framework's
  login-enabling link: Django's `POST /auth/google/link/`, and FastAPI's PKCE
  link flow with `allow_login: true`.

Intentional differences the contract does not hide:

- Django uses its users, password login, logout and database sessions; FastAPI
  uses Cross-Auth sessions and its own SQLModel users. Browser actions and
  profile/session checks are shared in `support/browser.ts`; framework files
  provide declarative routes/labels plus native startup and state access.
- Error pages differ (Django renders a page, FastAPI returns JSON or an inline
  message); scenarios assert the outcome and status.
- Which check refuses an unverified email first is the app's choice, so that
  scenario accepts any 4xx.
- Bearer tokens, the session inventory and the SPA flows exist only in FastAPI
  and stay in the FastAPI + SPA suite.

### Adding a framework

1. Make its example app able to run on a given port and database with Google
   pointed at `GOOGLE_EMULATOR_URL`.
2. Add `frameworks/<name>/app.ts` implementing `Framework` from
   `support/app.ts`: start the server and compose `createBrowserApp` from
   `support/browser.ts` with its routes and UI labels. Seed or read users
   through a small framework-native helper, such as Django's test-only
   management command or FastAPI's `state.py`. Don't reimplement browser actions
   in the framework file.
3. Add it to `frameworks/frameworks.ts`. The resolved project/worker
   configuration allocates its ports. Its project runs every scenario in
   `contract/`; put behavior only that framework has in
   `frameworks/<name>/*.spec.ts`.

Don't copy scenarios into a framework directory. If a scenario doesn't hold for
a framework, the difference belongs in this README and in a framework-specific
spec.

### Emulator limits

The emulator follows Google's OAuth and OpenID Connect endpoints, but it is not
a security oracle: it checks client secrets and PKCE, consumes codes once and
echoes the nonce, yet it does not bind codes to the client or redirect URI and
has no consent or denial screen. The library's adversarial cases (forged tokens,
browser binding, nonce and callback replays) stay in the Python tests and the
FastAPI + SPA suite. Testing against real Google with real credentials is still
a manual smoke test before releases.

## FastAPI + SPA suite

```bash
bun run test:e2e
bun run test:e2e:headed
```

Every scenario (including repeats and retries) starts its own local GitHub
emulator, `examples/fastapi` with a fresh temporary SQLite database, and
`examples/spa`. Backend ports are `8380 + parallelIndex`; SPA ports are
`9380 + parallelIndex`. No public provider, shared demo-account state or reused
servers are involved. An occupied port fails rather than using an unowned app.
Processes stop and temporary databases are removed after each scenario; server
logs stay beside failed traces in `test-results/`.

The fixture reuses the framework suite's process and FastAPI startup helpers.
`GITHUB_EMULATOR_URL` selects GitHub's local OAuth/API endpoints, while
`EXAMPLE_SPA_ORIGINS` supplies the owned SPA's CORS and OAuth callback origins.
Browser requests outside loopback fail the test (the browser-binding scenario
serves its synthetic cross-site form directly through Playwright routing).

It covers session and SPA sign-in with GitHub, bearer-token API access, account
linking, connecting and disconnecting, session management and revocation, and
OAuth browser binding. Link/connect scenarios assert the exact provider user,
email and login capability; bearer revocation is checked without a browser
cookie that could conceal rejection. Stale SPA response checks wait for the
named API-result region's `aria-busy` attribute to become false after response
handling, not a timer.

## Typecheck

```bash
bun run typecheck
```
