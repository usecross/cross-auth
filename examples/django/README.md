# Cross Auth Django example

The finished project from the
[Django guide](../../website/content/docs/django.md): Sign in with Google next
to Django's password login, connecting and disconnecting Google on a profile
page, and Django's own sessions and logout.

## Run it

1. Create a Google OAuth client of type **Web application** with the authorized
   redirect URI `http://127.0.0.1:8000/auth/google/callback`, as described in
   the guide.
2. Copy `.env.example` to `.env` and fill in the client ID and secret.
3. From this directory:

   ```bash
   set -a; source .env; set +a
   uv run python manage.py migrate
   uv run python manage.py runserver 127.0.0.1:8000
   ```

4. Open <http://127.0.0.1:8000/> (not `localhost`) and sign in.

`uv run` uses the Cross Auth source from this repository. To create a password
user to connect Google to, run `uv run python manage.py createsuperuser` or use
the shell command from the guide.

The project uses SQLite (`db.sqlite3`, ignored by Git) and Django's development
settings. See the guide's production checklist before deploying anything based
on it.
