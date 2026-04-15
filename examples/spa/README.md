# Cross-Auth SPA Example

A separate Vite + React frontend that authenticates against the FastAPI example
backend as if Cross-Auth were a standalone authentication server.

## What It Shows

- PKCE generation in the browser
- redirect to the backend generic provider authorize endpoint
- callback handling in a separate frontend app
- auth-code exchange at `/auth/token`
- client-side bearer token storage
- authenticated API call to the backend with `Authorization: Bearer ...`

## Run It

From the repo root, first start the backend demo:

```bash
cd examples/fastapi
uv sync --package cross-auth-fastapi-example
uv run --package cross-auth-fastapi-example fastapi dev main.py
```

Then, in another terminal:

```bash
cd examples/spa
bun install
bun run dev
```

Open `http://localhost:5173`.

## End-to-End Test

The SPA includes a Playwright end-to-end test that exercises both:

- session-social login on the FastAPI backend
- auth-code + token login from the separate SPA

Run it with both apps already running, or let Playwright start them
automatically:

```bash
cd examples/spa
bun install
bunx playwright install chromium
bun run test:e2e
```

## Default Backend Assumptions

The SPA assumes by default:

- backend base URL: `http://127.0.0.1:8000`
- provider: `github`
- client ID: `spa-example`

You can change the backend base URL and client ID in the UI.

## Callback URL

The SPA uses:

- `http://localhost:5173/callback`

That matches the trusted redirect hosts configured by the FastAPI example
backend.

## Why This Exists Separately

This app intentionally lives in `examples/spa` so it is visibly a different
application from the backend demo.

Over time, the same SPA should be reusable against other backend demos, such as:

- FastAPI
- Django
- Litestar

as long as they expose the same Cross-Auth auth-code + token flow.
