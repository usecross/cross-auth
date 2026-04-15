# Cross-Auth FastAPI Session Example

A small FastAPI app that demonstrates both password login and social login into
a browser session with Cross-Auth.

## What It Shows

- a local FastAPI app with in-memory users and social accounts
- password verification through `CrossAuth.authenticate(...)`
- browser session creation through `CrossAuth.login(...)`
- GitHub social login that completes directly into a browser session cookie
- session-backed protected routes with `get_current_user` and
  `require_current_user`

## Run It

From the repo root:

```bash
cd examples/fastapi
uv sync --package cross-auth-fastapi-example
uv run --package cross-auth-fastapi-example fastapi dev main.py
```

Open `http://127.0.0.1:8000`.

## Demo Notes

- Demo email: `demo@example.com`
- Demo password: `password123`
- The example uses `https://github-oauth-mock.fastapicloud.dev/` as a public
  mock GitHub OAuth provider
- On the mock GitHub page, enter `demo@example.com` to link the seeded demo
  user, or any other email to create a new in-memory local user
- Emails starting with `unverified` are treated as unverified by the mock
  provider
- The example uses in-memory storage, so restarting the app resets the user
  store and all sessions.

## Important Routes

- `/` - demo home page
- `/login` - signs in the seeded demo user with email/password
- `/auth/github/session/authorize` - starts GitHub social login into a browser
  session
- `/auth/github/session/callback` - provider callback that resolves the local
  user, creates the browser session, and redirects back signed in
- `/profile` - browser-only signed-in view
- `/api/me` - JSON view of the current signed-in user
- `/logout` - clears the browser session
