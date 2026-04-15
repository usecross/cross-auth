# Cross-Auth FastAPI Hybrid Backend Example

A FastAPI backend that demonstrates all three Cross-Auth configurations:

- **session app** for same-origin browser pages
- **auth server** for a separate frontend using auth code + `/auth/token`
- **hybrid** mode where the same backend supports both

## What It Shows

- a local FastAPI app with in-memory users and social accounts
- password verification through `CrossAuth.authenticate(...)`
- browser session creation through `CrossAuth.login(...)`
- GitHub social login that completes directly into a browser session cookie
- generic OAuth auth-code flow for a separate SPA client
- a session-protected API endpoint and a bearer-token-protected API endpoint

## Run It

From the repo root:

```bash
cd examples/fastapi
uv sync --package cross-auth-fastapi-example
uv run --package cross-auth-fastapi-example fastapi dev main.py
```

Open `http://127.0.0.1:8000`.

To run the separate SPA demo too:

```bash
cd examples/spa
bun install
bun run dev
```

Then open `http://localhost:5173`.

## Demo Notes

- Demo email: `demo@example.com`
- Demo password: `password123`
- SPA client ID: `spa-example`
- The example uses `https://github-oauth-mock.fastapicloud.dev/` as a public
  mock GitHub OAuth provider
- On the mock GitHub page, enter `demo@example.com` to link the seeded demo
  user, or any other email to create a new in-memory local user
- Emails starting with `unverified` are treated as unverified by the mock
  provider
- The example uses in-memory storage, so restarting the app resets the user
  store, social accounts, sessions, and tokens

## Important Routes

### Session-oriented web routes

- `/` - backend home page with session login options
- `/login` - signs in the seeded demo user with email/password
- `/auth/github/session/authorize` - starts GitHub social login into a browser
  session
- `/auth/github/session/callback` - provider callback that resolves the local
  user, creates the browser session, and redirects back signed in
- `/profile` - browser-only signed-in view
- `/logout` - clears the browser session
- `/api/me-session` - JSON view of the current signed-in user via session cookie

### Generic auth-server routes for the separate SPA

- `/auth/github/authorize` - starts the generic OAuth/auth-code flow
- `/auth/github/callback` - provider callback that issues a local auth code
- `/auth/token` - exchanges the local auth code for an access token
- `/api/me-token` - bearer-token-protected API endpoint

## How The Separate SPA Uses This Backend

The SPA in `examples/spa` performs this flow:

1. generate PKCE verifier + challenge in the browser
2. redirect to `/auth/github/authorize`
3. receive a local auth code at `http://localhost:5173/callback`
4. POST the code + verifier to `/auth/token`
5. store the returned access token client-side
6. call `/api/me-token` with `Authorization: Bearer ...`

So this backend demonstrates both Cross-Auth completion styles side by side:

- **session flow** via `/auth/github/session/authorize`
- **auth-code/token flow** via `/auth/github/authorize` + `/auth/token`
