# Cross-Auth FastAPI Session Example

A small FastAPI app that demonstrates session-based login with Cross-Auth.

## What It Shows

- a local FastAPI app with an in-memory demo user
- password verification through `CrossAuth.authenticate(...)`
- browser session creation through `CrossAuth.login(...)`
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
- The example uses in-memory storage, so restarting the app resets the user
  store and all sessions.

## Important Routes

- `/` - demo home page
- `/login` - signs in the demo user
- `/profile` - browser-only signed-in view
- `/api/me` - JSON view of the current signed-in user
- `/logout` - clears the browser session
