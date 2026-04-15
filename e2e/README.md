# Cross-Auth End-to-End Tests

This directory contains cross-app Playwright tests for the example applications.

Right now it covers the FastAPI hybrid backend and the separate SPA demo.

## What It Tests

- session-social login on the FastAPI backend
- auth-code + token login from the separate SPA
- bearer-authenticated API access from the SPA

## Run It

```bash
cd e2e
bun install
bunx playwright install chromium
bun run test:e2e
```

Headed mode:

```bash
bun run test:e2e:headed
```

The Playwright config starts:

- `examples/fastapi` on `http://127.0.0.1:8000`
- `examples/spa` on `http://127.0.0.1:5173`

unless they are already running locally.
