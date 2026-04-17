# Demo Plan: Cross-Auth Configuration Modes

## Goal

Show the three intended ways to use Cross-Auth:

1. **Session app**: one web app handles both business logic and authentication,
   using browser sessions.
2. **Auth server**: a separate frontend authenticates against Cross-Auth using
   the OAuth-style auth-code + token flow.
3. **Hybrid**: the same backend supports both session-based web auth and
   token-based external clients.

## Current State

Today, the library supports these shapes best in FastAPI:

- **Session app** via `CrossAuth` session helpers and session-social routes
- **Auth server** via the generic provider routes and `/token`
- **Hybrid** by exposing both sets of routes from the same FastAPI app

Future framework demos can be added for Django, Litestar, and others once their
integrations exist.

## Recommendation

Do **not** build three separate demos immediately.

Instead, make the examples directory reflect the long-term structure:

- `examples/fastapi/` becomes the **hybrid backend demo**
- `examples/spa/` becomes the **separate frontend demo app**

Together they should show all three modes:

- the server-rendered/session part of `examples/fastapi` demonstrates the
  **session app** mode
- `examples/spa` demonstrates the **auth server** mode against that backend
- both talking to the same backend demonstrates the **hybrid** mode

This keeps the example structure future-friendly and makes it obvious that the
SPA is a distinct client application.

## Proposed Demo Layout

### `examples/fastapi/`

This should replace the current session-only example.

It should become the canonical FastAPI backend demo and expose both:

- session-oriented web routes for same-origin/browser usage
- generic OAuth/token routes for external clients

Suggested contents:

- FastAPI app using `CrossAuth`
- in-memory users, social accounts, and sessions
- server-rendered pages for session login
- protected JSON endpoints for both session and bearer-token access
- GitHub provider configured against the public mock provider
- README explaining both the session and auth-server sides of the demo

### `examples/spa/`

This should be a separate frontend application, built with **Vite + React**.

Its role is to make the auth-server flow explicit:

- it performs PKCE in the browser
- redirects to the backend provider authorize endpoint
- handles the frontend callback
- exchanges the local auth code at `/token`
- stores the returned token client-side
- calls protected API endpoints with `Authorization: Bearer ...`

This app should be designed so it can later point at other demo backends too,
such as:

- FastAPI
- Django
- Litestar

So it should avoid FastAPI-specific assumptions where possible, other than
initial configuration values.

## What the Combined Demo Should Show

### A. Session flow (same-origin web app)

Served by `examples/fastapi`.

Pages and routes:

- `/` login page
- `/profile` protected page
- `/login` password login
- `/auth/github/session/authorize` social login to session
- `/logout`

What it demonstrates:

- `CrossAuth.authenticate(...)`
- `CrossAuth.login(...)`
- browser session cookies
- social login directly into session cookie

### B. Auth server flow (separate frontend)

Driven by `examples/spa`, talking to `examples/fastapi`.

Frontend flow:

1. generate PKCE verifier/challenge
2. redirect to backend `/{provider}/authorize`
3. receive local auth code at frontend callback page
4. POST to backend `/token`
5. store access token client-side
6. call protected API with `Authorization: Bearer ...`

What it demonstrates:

- Cross-Auth as a standalone authentication service
- generic OAuth/provider flow
- auth code + token exchange
- separate frontend/backend deployment model

### C. Hybrid mode

Demonstrated by running both apps together.

What it demonstrates:

- one backend supports both:
  - session-based browser login
  - token-based external clients
- the route choice determines the completion style:
  - `/{provider}/session/authorize` -> session cookie
  - `/{provider}/authorize` -> auth code -> `/token`

## Important Implementation Note

Cross-Auth issues tokens through `create_token(...)`, but token verification for
protected APIs is still application-owned.

So the FastAPI backend demo should include a very small example of:

- token creation (already required)
- token verification for bearer-protected API routes

A simple JWT example is enough for the demo.

## Suggested Scope

### FastAPI backend (`examples/fastapi`)

- in-memory users, social accounts, and sessions
- GitHub provider configured against the public mock provider
- session page(s)
- `/api/me-session` protected by session cookie
- `/api/me-token` protected by bearer token
- `/auth/...` routes from `CrossAuth.router`
- `trusted_origins` configured for the SPA origin
- minimal token verification helper for bearer-protected routes

### SPA frontend (`examples/spa`)

- Vite + React app
- configurable backend base URL
- one screen with:
  - "Login with GitHub" button
  - callback handling page
  - token display/debug info
  - button to call `/api/me-token`
- clear separation between:
  - unauthenticated state
  - exchanging code state
  - authenticated/token-present state
- optionally include logout/token clearing in v1

## Why `examples/spa` Should Be Separate

Using `examples/spa` instead of nesting the frontend under the FastAPI example
makes the architecture clearer:

- the SPA is visibly a different application
- the backend/frontend boundary is easier to understand
- the SPA can later be reused against future Django, Litestar, or other demos
- the directory layout mirrors the mental model of Cross-Auth as either:
  - part of your app, or
  - a separate auth service

## Provider for Demos

Use the public mock provider:

- `https://github-oauth-mock.fastapicloud.dev/`

This keeps the demos deterministic and easy to run locally.

## Demo Narrative for Docs

The docs should eventually present the modes in this order:

1. **Session app** — easiest, most common for server-rendered apps
2. **Auth server** — for SPAs/mobile apps with separate frontend
3. **Hybrid** — one backend serving both browser sessions and API clients

This mirrors increasing architectural complexity.

The examples should then map to that narrative like this:

- `examples/fastapi` shows session mode by itself when viewed alone
- `examples/spa` + `examples/fastapi` together show auth-server and hybrid mode

## Incremental Delivery Plan

### Phase 1

Replace the current `examples/fastapi` demo with a hybrid-capable backend while
preserving the session-oriented pages.

Deliverables:

- keep password login
- keep social login to session
- add bearer-token-protected API example
- document the generic OAuth/token flow in the README

### Phase 2

Add `examples/spa` as a separate Vite + React app.

Deliverables:

- PKCE generation
- provider redirect
- callback handling
- `/token` exchange
- bearer token storage
- call to protected backend API

### Phase 3

Make `examples/spa` configurable enough to point at different demo backends.

Deliverables:

- backend base URL config
- client ID config if needed
- route/path assumptions kept minimal

### Phase 4

Once other framework integrations exist, add equivalent backend demos for:

- Django
- Litestar
- others

At that point, `examples/spa` can be reused to show the auth-server/hybrid story
across frameworks.

## Success Criteria

A user should be able to look at the examples and quickly understand:

- when to use session routes vs OAuth/token routes
- that both can coexist in one backend
- what extra responsibilities exist in auth-server/hybrid mode
- how little application code is needed in the session case
- that a separate frontend can authenticate against the same backend without
  sharing code or runtime
