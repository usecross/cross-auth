# Cross Auth Django example

The project from the [Django guide](../../website/content/docs/django.md): Sign
in with Google next to Django's password login, connecting and disconnecting
Google on a profile page, and Django's own sessions and logout.

The settings, URLs, signals and Cross Auth wiring follow the guide. The pages
are React components in [`../frontend`](../frontend), shared with the FastAPI
example and rendered with [cross-inertia](https://github.com/usecross/cross-inertia)
instead of the guide's Django templates: `core/views.py` renders them with
`cross_inertia.django.render`, `core/inertia.py` shares the CSRF token, the
signed-in user and URLs with every page, and `core.views.LoginView` is Django's
`LoginView` with its form rendered by the frontend.

## Run it

1. Create a Google OAuth client of type **Web application** with the authorized
   redirect URI `http://127.0.0.1:8000/auth/google/callback`, as described in
   the guide.
2. Copy `.env.example` to `.env` and fill in the client ID and secret.
3. Install the frontend once: `cd ../frontend && bun install`. With `DEBUG`,
   `runserver` starts its Vite dev server on port 5174; set `INERTIA_DEV=0` and
   run `bun run build` there to serve the built bundle instead.
4. From this directory:

   ```bash
   set -a; source .env; set +a
   uv run python manage.py migrate
   uv run python manage.py runserver 127.0.0.1:8000
   ```

5. Open <http://127.0.0.1:8000/> (not `localhost`) and sign in.

`uv run` uses the Cross Auth source from this repository. To try disconnecting
and connecting Google with a password account, follow Steps 10 to 13 of the
guide, which give your Google user a password with
`uv run python manage.py changepassword` instead of creating another user.

`core/signals.py` connects receivers to Cross Auth's Django signals, as in Step
14 of the guide: it prints a line for each new user, and refuses Google accounts
outside `ALLOWED_EMAIL_DOMAIN`, before anything is written, when you set that
variable in `.env`. Unset, everyone may sign in.

The project uses SQLite (`db.sqlite3`, ignored by Git) and Django's development
settings. See the guide's production checklist before deploying anything based
on it.
