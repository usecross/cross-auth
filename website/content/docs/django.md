---
title: Django
description:
  Add Sign in with Google to a Django project while Django keeps its own users,
  sessions, and permissions.
order: 5
section: Guides
---

## Overview

This guide builds a Django project, step by step, where people can:

- sign in with Google, creating a Django user on first sign-in;
- keep at least one way to sign in when disconnecting Google;
- sign in with a Django password, then connect Google to the same user;
- sign out with Django's own logout;
- run your own code around Google sign-ins, connections and disconnections with
  Django signals.

Cross Auth only handles the conversation with Google and stores which Google
account belongs to which Django user. Django keeps owning everything else: the
user model, passwords, permissions, `request.user`, middleware, sessions,
`login()` and `logout()`. There is no FastAPI, SQLModel, Redis, or second login
cookie involved.

The finished project is in
[`examples/django`](https://github.com/usecross/cross-auth/tree/main/examples/django).

> **Pilot scope:** this integration is new. It supports Google, Django 5.2 LTS
> (5.2.8 or later), Python 3.11 to 3.14, database-backed Django sessions, and
> SQLite or PostgreSQL. It is tested with Django's test client against a mocked
> Google that signs real ID tokens; sign-in against Google itself is a manual
> step you do in this guide. Other providers, Django 6, and multi-factor
> authentication are not supported yet. See
> [Limitations](#limitations-and-support).

## Prerequisites

- Python 3.11–3.14 and [uv](https://docs.astral.sh/uv/). The commands below
  select Python 3.13 so that `uv` does not choose an untested newer version.
- A Google account that can create a project in the
  [Google Cloud console](https://console.cloud.google.com/).

## Step 1: Create the project

Create an empty project and install Cross Auth with its `django` extra, which
also installs Django 5.2:

```bash
mkdir django-google-demo
cd django-google-demo
uv init --bare --python 3.13
uv python pin 3.13
uv add "cross-auth[django]>=0.38.0"
```

> **Version:** this guide requires Cross Auth 0.38.0 or later, which includes
> the native Google sign-in views and Django signals.

Create a Django project in the current directory and an app for your pages:

```bash
uv run django-admin startproject config .
uv run python manage.py startapp core
```

## Step 2: Decide on your user model

Cross Auth works with Django's default user model or your own. This guide uses
the default one.

If you want a custom user model, create it and set `AUTH_USER_MODEL` **before
the first `migrate`**, as Django requires; switching later is a manual data
migration. Cross Auth's tables reference `settings.AUTH_USER_MODEL`, and custom
models need a small user factory, shown in
[Custom user models](#custom-user-models).

## Step 3: Configure settings

Open `config/settings.py`. At the top, import the Google provider and `os`:

```python
import os

from cross_auth.social_providers.google import GoogleProvider
```

Add Cross Auth's app and yours to `INSTALLED_APPS`:

```python
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "cross_auth.django",
    "core.apps.CoreConfig",
]
```

`core.apps.CoreConfig` is the app configuration that `startapp` generated; Step
14 uses its `ready()` method.

Keep the `MIDDLEWARE` that `startproject` generated. Cross Auth needs
`SessionMiddleware`, `CsrfViewMiddleware` and `AuthenticationMiddleware`, all of
which are there, and Django's default database-backed sessions.

Then add these settings at the end of the file:

```python
AUTHENTICATION_BACKENDS = [
    # Password sign-in, as before.
    "django.contrib.auth.backends.ModelBackend",
    # Restores users who signed in with Google on later requests.
    "cross_auth.django.backends.CrossAuthBackend",
]

LOGIN_URL = "login"
LOGIN_REDIRECT_URL = "home"
LOGOUT_REDIRECT_URL = "home"

CROSS_AUTH = {
    "PROVIDERS": [
        GoogleProvider(
            client_id=os.environ["GOOGLE_CLIENT_ID"],
            client_secret=os.environ["GOOGLE_CLIENT_SECRET"],
        ),
    ],
}
```

`CrossAuthBackend` never checks credentials itself; its `authenticate()` always
returns `None`. Cross Auth records it on sessions it starts after verifying
Google's response, and Django uses it to load `request.user` on later requests.
Like `ModelBackend`, it refuses inactive users and grants the user's model and
group permissions.

The client ID and secret come from environment variables, which you will create
in Step 5. Django does not read `.env` files on its own.

## Step 4: Create the database tables

Set placeholder credentials for now, so the settings load, and run the
migrations:

```bash
export GOOGLE_CLIENT_ID=placeholder GOOGLE_CLIENT_SECRET=placeholder
uv run python manage.py migrate
```

Besides Django's own tables, this creates `cross_auth_socialaccount`, which
links Google accounts to your users, and `cross_auth_expiringvalue`, which holds
short-lived sign-in state and Google's public signing keys. Existing users and
tables are not changed, so you can add Cross Auth to a project that already has
users.

## Step 5: Create a Google OAuth client

Google needs to know your application and where to send people back after they
sign in. Do this in the
[Google Cloud console](https://console.cloud.google.com/)
([Google's guide](https://developers.google.com/workspace/guides/configure-oauth-consent)):

1. Create a project, or select one you use for development.
2. Open **Google Auth Platform → Branding**. If it shows **Get started**, click
   it and fill in:
   - **App information:** an app name and a user support email.
   - **Audience:** choose **External** so any Google account can sign in.
     (**Internal** is only available to Google Workspace organizations and
     limits sign-in to their members.)
   - **Contact information:** your email.
   - Agree to the Google API Services User Data Policy, then click **Create**.
3. Open **Data Access → Add or remove scopes** and select only `openid`,
   `.../auth/userinfo.email` and `.../auth/userinfo.profile`. Save. These are
   the scopes `GoogleProvider` asks for.
4. Open **Clients → Create client**:

   - **Application type:** Web application.
   - **Name:** for example "Django development".
   - Under **Authorized redirect URIs**, click **Add URI** and enter exactly:

     ```text
     http://127.0.0.1:8000/auth/google/callback
     ```

     There is no trailing slash. Google compares the scheme, host, port and path
     character for character, and `localhost` and `127.0.0.1` count as different
     hosts. You do not need **Authorized JavaScript origins**.

   - Click **Create**.

5. Copy the **client ID** and **client secret** right away. Google shows the
   full secret only once; if you lose it, add a new secret to the client.

New apps start in **Testing** mode. Google's
[audience rules](https://support.google.com/cloud/answer/15549945) usually limit
a testing app to listed test users, but apps that request only `openid`, email
and profile, like this one, are exempt. If you add other scopes later, add your
account under **Audience → Test users**.

Store the credentials in a `.env` file next to `manage.py`, and keep it out of
version control:

```bash
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-client-secret
```

```bash
echo ".env" >> .gitignore
```

## Step 6: Add the URLs

Replace `config/urls.py` with:

```python
from django.contrib import admin
from django.urls import include, path

from core import views

urlpatterns = [
    path("admin/", admin.site.urls),
    path("accounts/", include("django.contrib.auth.urls")),
    path("auth/", include("cross_auth.django.urls")),
    path("profile/", views.profile, name="profile"),
    path("", views.home, name="home"),
]
```

`django.contrib.auth.urls` gives you Django's password login and logout views
under `accounts/`. Cross Auth's URLs live under the `cross_auth` namespace:

| URL                                         | Name                    | Method |
| ------------------------------------------- | ----------------------- | ------ |
| `auth/<provider>/login/`                    | `cross_auth:login`      | POST   |
| `auth/<provider>/link/`                     | `cross_auth:link`       | POST   |
| `auth/<provider>/callback`                  | `cross_auth:callback`   | GET    |
| `auth/<provider>/accounts/<id>/disconnect/` | `cross_auth:disconnect` | POST   |

The login, link and disconnect views accept only POST requests with Django's
CSRF token, and an optional `next` path to return to. Google redirects the
browser to the callback, which is the redirect URI you registered in Step 5. If
you mount the URLs under a different prefix than `auth/`, register that path
instead.

## Step 7: Add views and templates

Replace `core/views.py` with:

```python
from django.contrib.auth.decorators import login_required
from django.shortcuts import render


def home(request):
    return render(request, "core/home.html")


@login_required
def profile(request):
    return render(request, "core/profile.html")
```

Create `core/templates/core/base.html`:

```django
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Cross Auth Django example</title>
  </head>
  <body>
    {% block content %}{% endblock %}
  </body>
</html>
```

Create `core/templates/core/home.html`. Signing in starts with a POST form, not
a link, so the request carries Django's CSRF token:

```django
{% extends "core/base.html" %}

{% block content %}
  {% if user.is_authenticated %}
    <p>Signed in as {{ user.get_username }}.</p>
    <p><a href="{% url 'profile' %}">Your profile</a></p>
    <form method="post" action="{% url 'logout' %}">
      {% csrf_token %}
      <button type="submit">Sign out</button>
    </form>
  {% else %}
    <form method="post" action="{% url 'cross_auth:login' 'google' %}">
      {% csrf_token %}
      <input type="hidden" name="next" value="{% url 'profile' %}">
      <button type="submit">Sign in with Google</button>
    </form>
    <p><a href="{% url 'login' %}">Sign in with a password</a></p>
  {% endif %}
{% endblock %}
```

Create `core/templates/core/profile.html`. It lists the user's connected
accounts, which Cross Auth exposes as `user.cross_auth_social_accounts`, with a
form to connect Google and one to disconnect each account:

```django
{% extends "core/base.html" %}

{% block content %}
  <h1>{{ user.get_username }}</h1>

  <h2>Connected accounts</h2>
  <ul>
    {% for account in user.cross_auth_social_accounts.all %}
      <li>
        {{ account.provider }}: {{ account.provider_email }}
        <form method="post"
              action="{% url 'cross_auth:disconnect' account.provider account.pk %}">
          {% csrf_token %}
          <input type="hidden" name="next" value="{% url 'profile' %}">
          <button type="submit">Disconnect</button>
        </form>
      </li>
    {% empty %}
      <li>None yet.</li>
    {% endfor %}
  </ul>

  <form method="post" action="{% url 'cross_auth:link' 'google' %}">
    {% csrf_token %}
    <input type="hidden" name="next" value="{% url 'profile' %}">
    <button type="submit">Connect Google</button>
  </form>

  <form method="post" action="{% url 'logout' %}">
    {% csrf_token %}
    <button type="submit">Sign out</button>
  </form>
{% endblock %}
```

Django ships no template for its password login view, so create
`core/templates/registration/login.html`:

```django
{% extends "core/base.html" %}

{% block content %}
  <h1>Sign in with a password</h1>
  <form method="post">
    {% csrf_token %}
    {{ form.as_p }}
    <input type="hidden" name="next" value="{{ next }}">
    <button type="submit">Sign in</button>
  </form>
{% endblock %}
```

## Step 8: Run the server

Load your real credentials into the shell and start Django's development server:

```bash
set -a; source .env; set +a
uv run python manage.py runserver 127.0.0.1:8000
```

Open [http://127.0.0.1:8000/](http://127.0.0.1:8000/). Use this exact address,
not `localhost:8000`: the redirect URI sent to Google is built from the address
in your browser, and sign-in state is kept in cookies for that host.

## Step 9: Sign in with Google

Click **Sign in with Google**, choose your Google account, and approve the
consent screen if Google shows one. You land on your profile page, signed in.

What happened:

1. The POST to `/auth/google/login/` passed Django's CSRF check. Cross Auth
   stored a short-lived, single-use sign-in state, set a temporary cookie named
   `cross_auth_oauth_<state>` that ties the attempt to your browser, and
   redirected you to Google with PKCE and a nonce.
2. Google redirected back to `/auth/google/callback`. Cross Auth checked the
   state, the browser cookie, the PKCE verifier, and the signature, audience,
   issuer and nonce of Google's ID token, then deleted the temporary cookie.
3. On your first sign-in, it created a Django user and the Google account link
   in one database transaction. The user has your Google email as username and
   email, and no usable password.
4. It called `django.contrib.auth.login()`, which gave the session a new key,
   replacing any anonymous session you had, and stored it through Django's
   session backend.

Your browser now holds Django's `sessionid` and `csrftoken` cookies and nothing
else. Open [http://127.0.0.1:8000/profile/](http://127.0.0.1:8000/profile/) in a
new tab; `@login_required` and `request.user` work as with any Django login.

The rest of this guide continues with this user, so keep the development
database and stay signed in.

## Step 10: Try to disconnect your only way to sign in

On your profile, click **Disconnect** next to Google. Cross Auth refuses with
`no_alternative_login_method` and keeps the connection: the user signed up
through Google and has no usable password, so disconnecting would leave no way
to sign in. Go back to your profile; Google is still listed.

A usable Django password counts as another way to sign in. If your site has no
password sign-in, set `"PASSWORD_LOGIN": False` in `CROSS_AUTH` so that a
password never counts.

## Step 11: Give your development user a password

To see disconnecting and connecting with a password account, give this
development user a password with Django's `changepassword` command. Its username
is your Google email; replace `you@gmail.com`:

```bash
uv run python manage.py changepassword 'you@gmail.com'
```

The command prompts for the new password twice, so it is not saved in your shell
history.

> **Warning:** `changepassword` is an administrator command for your local
> development database. It is not a way for people to recover or set a password
> in production; use Django's password reset or password change views for that.

Changing a password ends the user's existing sessions, as Django always does.
Reload your profile: you are signed out. Sign in at
[http://127.0.0.1:8000/accounts/login/](http://127.0.0.1:8000/accounts/login/)
with your Google email as the username and the new password. You are back on the
same profile, with Google still connected.

## Step 12: Disconnect Google

Click **Disconnect** next to Google again. The user now has a password, so the
Google connection is removed. The Django user, its password and any data your
application stores for it stay in place.

Sign out, then click **Sign in with Google** on the home page. Cross Auth shows
an `account_not_linked` error: a user with your Google email exists, but Cross
Auth never attaches a Google account to an existing user just because the email
addresses match. Signing in and connecting Google is up to the user.

## Step 13: Connect Google to the password account

1. Sign in at
   [http://127.0.0.1:8000/accounts/login/](http://127.0.0.1:8000/accounts/login/)
   with your password.
2. On your profile, click **Connect Google** and pick the same Google account.
3. Back on the profile, Google is listed under **Connected accounts** again.
4. Sign out, then click **Sign in with Google** on the home page. You are signed
   in as the same user as before.

Connecting requires Google to report the email as verified and to match the
user's email, ignoring case. To let people connect a Google account with a
different email, set `"ACCOUNT_LINKING": {"allow_different_emails": True}` in
`CROSS_AUTH`. A Google account can belong to only one user; connecting one that
another user already has fails with `account_already_linked`.

Click **Sign out** when you are done. Django's `LogoutView` ends the session.
You are still signed in to Google itself, so the next sign-in may skip Google's
account chooser.

## Step 14 (optional): Run code around sign-in

Cross Auth sends
[Django signals](https://docs.djangoproject.com/en/5.2/topics/signals/) around
Google sign-ups and sign-ins. Receivers can refuse one by raising Django's
`PermissionDenied`, which answers with Django's 403 page, or react once it is
saved.

Create `core/signals.py`:

```python
import os

from django.core.exceptions import PermissionDenied
from django.dispatch import receiver

from cross_auth.django.signals import before_callback, user_created

# For example ALLOWED_EMAIL_DOMAIN=example.com. Unset, everyone may sign in.
ALLOWED_EMAIL_DOMAIN = os.environ.get("ALLOWED_EMAIL_DOMAIN")


@receiver(before_callback)
def only_company_accounts(sender, email, email_verified, **kwargs):
    if ALLOWED_EMAIL_DOMAIN and not (
        email_verified and (email or "").lower().endswith("@" + ALLOWED_EMAIL_DOMAIN)
    ):
        raise PermissionDenied("Use your company account.")


@receiver(user_created)
def welcome(sender, user, **kwargs):
    print(f"Welcome, new user {user.pk} ({user.email})")
```

Replace `core/apps.py`, so Django connects the receivers once its apps are
loaded:

```python
from django.apps import AppConfig


class CoreConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "core"

    def ready(self):
        from . import signals  # noqa: F401
```

Restart the server and sign up with a new Google account: the terminal prints
the welcome line. To try the rule, add `ALLOWED_EMAIL_DOMAIN=example.com` to
`.env`, load it again as in Step 8 and restart: signing in with any other Google
account, new or known, now shows Django's 403 page, and you stay signed out.
Connecting such an account is refused the same way.

`before_callback` is sent once Google's response is verified and before Cross
Auth looks up or writes anything, so a refusal there creates no user and
connects nothing. Its `email` is the one Google reported. To refuse only new
users, use `before_user_create`; to refuse only logins of existing users,
`before_login`. On a first sign-in the user and its Google connection already
exist when `before_login` is sent, so refusing there leaves them in place.

Cross Auth sends these signals only for its Google flows; other signals cover
starting a sign-in and connecting or disconnecting Google. Django's own
`user_logged_in` and `user_logged_out` signals cover every login and logout,
including password logins, and are sent as usual. See the
[signals reference](#signals-reference).

## Custom user models

Cross Auth creates users with your user model's default manager. The default
factory works with models managed by Django's `UserManager`, including
`AbstractUser` subclasses: it uses the email as username and sets no usable
password.

For other models, such as one whose manager requires extra fields, set
`CREATE_USER` to the dotted path of a function:

```python
# core/users.py
from core.models import Profile, User


def create_user(*, email, user_info, extra_fields):
    user = User.objects.create_user(
        email=email,
        display_name=user_info.get("name") or email.split("@")[0],
    )
    Profile.objects.create(user=user)
    return user
```

```python
CROSS_AUTH = {
    "PROVIDERS": [...],
    "CREATE_USER": "core.users.create_user",
}
```

The factory runs inside the transaction that also stores the Google account
link, so if it raises, neither the user nor the rows it created are saved. Do
not call external services from it; use a `user_created` receiver, which runs
after the transaction commits. `extra_fields` is always empty. Custom primary
keys, such as UUIDs, are supported.

## Sessions

Django's session table has no user column and keeps everything in an encoded
blob, so it cannot tell a user where they are signed in. Cross Auth's session
engine stores Django's sessions in its own table instead, with the user, how
they signed in, their browser and IP address, and when the session was last
used. Your views can then list a user's sessions and sign any of them out.

### Set up the session engine

Point `SESSION_ENGINE` at Cross Auth and replace Django's `SessionMiddleware`
with Cross Auth's, in the same place:

```python
SESSION_ENGINE = "cross_auth.django.sessions"

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    # Instead of django.contrib.sessions.middleware.SessionMiddleware:
    "cross_auth.django.sessions.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    # ...
]
```

`migrate` creates the `cross_auth_session` table. Keep `django.contrib.sessions`
in `INSTALLED_APPS`: its `clearsessions` command deletes expired sessions from
Cross Auth's table too. Sessions in `django_session` are not moved, so everyone
signs in again after you switch. Django's `check` command warns
(`cross_auth.W002`, `cross_auth.W003`) when the engine and the middleware are
not used together.

Each time Django saves a session, Cross Auth fills these columns of
`cross_auth.django.models.Session`:

| Column          | Value                                                                                                                                                                                                                                                                                   |
| --------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `user`          | The signed-in user, or `None` while the visitor is anonymous.                                                                                                                                                                                                                           |
| `login_method`  | The provider, such as `"google"`, for a sign-in through Cross Auth; `None` for other logins, such as Django's password login. A later password login in the same browser sets it back to `None`.                                                                                        |
| `user_agent`    | The browser's `User-Agent` header, without control characters and cut to 512 characters.                                                                                                                                                                                                |
| `ip`            | The request's `REMOTE_ADDR`; see [behind a proxy](#behind-a-proxy).                                                                                                                                                                                                                     |
| `created_at`    | When the user signed in, or when an anonymous session started. Each login sets it again, even when Django keeps the session key. A new key without a login, such as after a password change, keeps it.                                                                                  |
| `last_activity` | When a request last used the session. Saving the session sets it; otherwise it is updated at most once a minute (`SESSION_ACTIVITY_INTERVAL`), and only by requests that read the session or the user.                                                                                  |
| `public_id`     | A random ID that names the session on your pages, because `session_key` is the session cookie itself and must never be shown. Like `created_at`, each login gives a new one and a new key without a login keeps it, so a page listing the sessions stays valid after a password change. |

Logging out, `clearsessions` and deleting a user delete their rows.

### List and revoke sessions

`cross_auth.django.sessions` has three helpers for the signed-in user's
sessions. They take the request, so they always act on `request.user`'s own
sessions and know which one is current:

- `list_sessions(request)` returns the user's sessions, newest first, as
  `SessionInfo` objects with `id`, `login_method`, `user_agent`, `ip`,
  `created_at`, `last_activity`, `expires_at` and `is_current`. Expired sessions
  and sessions that a password change ended are left out. Anonymous requests get
  an empty list.
- `revoke_session(request, session_id)` signs out the session whose `id` is
  `session_id` and returns whether it found one. Another user's session is never
  touched. Revoking the current session logs out with Django's `logout()`.
- `revoke_other_sessions(request)` signs out all of the user's other sessions,
  keeps the current one, and returns how many it revoked.

For example, a page that lists the sessions with a button to sign out each one,
and one to sign out everywhere else:

```python
# core/views.py
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render
from django.views.decorators.http import require_POST

from cross_auth.django.sessions import (
    list_sessions,
    revoke_other_sessions,
    revoke_session,
)


@login_required
def sessions(request):
    return render(request, "core/sessions.html", {"sessions": list_sessions(request)})


@require_POST
@login_required
def revoke(request):
    if "session" in request.POST:
        revoke_session(request, request.POST["session"])
    else:
        revoke_other_sessions(request)
    return redirect("sessions")
```

```python
# config/urls.py
urlpatterns = [
    # ...
    path("sessions/", views.sessions, name="sessions"),
    path("sessions/revoke/", views.revoke, name="revoke_session"),
]
```

```html
<!-- core/templates/core/sessions.html -->
{% extends "core/base.html" %} {% block content %}
<h1>Where you're signed in</h1>
<ul>
  {% for session in sessions %}
  <li>
    {{ session.user_agent|default:"Unknown browser" }} {% if
    session.login_method %}· signed in with {{ session.login_method }}{% endif
    %} · active {{ session.last_activity|timesince }} ago {% if session.ip %}·
    {{ session.ip }}{% endif %} {% if session.is_current %} (this browser) {%
    else %}
    <form method="post" action="{% url 'revoke_session' %}">
      {% csrf_token %}
      <input type="hidden" name="session" value="{{ session.id }}" />
      <button type="submit">Sign out</button>
    </form>
    {% endif %}
  </li>
  {% endfor %}
</ul>

<form method="post" action="{% url 'revoke_session' %}">
  {% csrf_token %}
  <button type="submit">Sign out everywhere else</button>
</form>
{% endblock %}
```

`user_agent` is the header as the browser sent it. To show "Chrome on macOS",
parse it with a library such as
[`ua-parser`](https://pypi.org/project/ua-parser/). For staff tools, query the
model directly; for example, `Session.objects.filter(user=user).delete()` signs
a user out everywhere.

### Behind a proxy

The `ip` column is the request's `REMOTE_ADDR`. Behind a load balancer or
reverse proxy, that is the proxy's address. Cross Auth never reads
`X-Forwarded-For` itself, because clients can send that header too. If your
proxy sets it, have your server use it (for example
`uvicorn --proxy-headers --forwarded-allow-ips=...`), or copy the address your
proxy added into `REMOTE_ADDR` in a middleware listed before Cross Auth's
`SessionMiddleware`:

```python
# core/middleware.py
def client_ip(get_response):
    def middleware(request):
        # Only behind exactly one proxy that always sets this header: the last
        # address is the one it added; the others came from the client.
        forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
        if forwarded:
            request.META["REMOTE_ADDR"] = forwarded.rsplit(",", 1)[-1].strip()
        return get_response(request)

    return middleware
```

### Limitations

- Only the database engine is provided: there is no cache or `cached_db`
  variant, so every request that reads the session queries the database, as with
  Django's `db` engine.
- A session's `user_agent` and `ip` are those of the request that last saved it
  or updated its activity.

## Signals reference

`cross_auth.django.signals` defines the signals below. Their sender is your user
model. Every receiver gets `request`, the view's `HttpRequest`, and `provider`,
such as `"google"`, plus the arguments listed. Write receivers with `**kwargs`
so that new arguments do not break them.

`before_*` signals get plain values: IDs are strings and nothing is a model
instance, so a receiver cannot change what Cross Auth is about to do except by
refusing. The other signals are sent once the change is committed and get model
instances: your user model, or `cross_auth.django.models.SocialAccount` (the
Google connection, with `user_id`, `provider_user_id`, `provider_email`,
`provider_email_verified` and `is_login_method`). Use `.pk` on them.

| Signal                             | Sent                                                                                                                                                          | Arguments                                                                                                                   |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `before_authorization`             | By the login and link views, before they store anything and redirect to Google.                                                                               | `flow` (`"login"` or `"link"`), `user_id` (the signed-in user's for `"link"`, `None` for `"login"`)                         |
| `authorization_started`            | After the view stored the sign-in attempt, just before the redirect.                                                                                          | `flow`; for `"link"`, `request.user` is the user linking                                                                    |
| `before_callback`                  | When Google's callback is verified (state, browser, PKCE code exchange, ID token signature and nonce), before any user or connection is looked up or written. | `flow`, `provider_user_id`, `email` and `email_verified` as Google reported them, `user_id` (as for `before_authorization`) |
| `before_user_create`               | Before a first sign-in creates a user. Nothing is written yet.                                                                                                | `email` (normalized), `email_verified`                                                                                      |
| `user_created`                     | After the user, the rows your `CREATE_USER` factory wrote and the Google connection are committed.                                                            | `user`                                                                                                                      |
| `before_social_account_create`     | Before a Google account is connected to a user: at sign-up, inside its transaction, or by a link.                                                             | `user_id`, `provider_user_id`, `email`, `email_verified`, `is_login_method`                                                 |
| `social_account_created`           | After the new connection is committed.                                                                                                                        | `social_account`                                                                                                            |
| `before_social_account_update`     | Before a connection is refreshed with Google's latest email: on every later sign-in, and when a link reconnects it.                                           | `social_account_id`, `user_id`, `provider_user_id`, the new `email` and `email_verified`, the stored `is_login_method`      |
| `social_account_updated`           | After the refresh is committed.                                                                                                                               | `social_account`                                                                                                            |
| `social_account_linked`            | After a link's connection is committed, following `social_account_created` or `social_account_updated`. Never sent by sign-ins.                               | `social_account`                                                                                                            |
| `before_login`                     | Before Django's `login()`, once the user is known.                                                                                                            | `user_id`, `email` (the user's, or `None`)                                                                                  |
| `after_login`                      | After `login()` and after the session is saved to the database.                                                                                               | `user`                                                                                                                      |
| `before_social_account_disconnect` | Before the disconnect view removes one of the signed-in user's connections.                                                                                   | `social_account_id`, `user_id`, `provider_user_id`                                                                          |
| `social_account_disconnected`      | After the removal is committed. Not sent when the connection was the user's last way to sign in and stayed.                                                   | `social_account`, the removed row; its `pk` and `user_id` still name it                                                     |

The flows send them in this order:

| Flow           | Signals                                                                                                                                                                                                                                                                            |
| -------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| First sign-in  | `before_authorization`, `authorization_started`, `before_callback`, `before_user_create`, `before_social_account_create`, `user_created`, `social_account_created`, `before_login`, `user_logged_in`, `after_login`                                                                |
| Later sign-in  | `before_authorization`, `authorization_started`, `before_callback`, `before_social_account_update`, `social_account_updated`, `before_login`, `user_logged_in`, `after_login`                                                                                                      |
| Connect Google | `before_authorization`, `authorization_started`, `before_callback`, `before_social_account_create`, `social_account_created`, `social_account_linked`; for a connection the user already has, `before_social_account_update` and `social_account_updated` instead of the first two |
| Disconnect     | `before_social_account_disconnect`, `social_account_disconnected`                                                                                                                                                                                                                  |

`user_logged_in` is Django's own signal, sent by `login()`.

- **Refusing.** Raise `PermissionDenied` from any `before_*` receiver. Django
  answers with its 403 page and the step does not happen: no state is stored,
  nobody is created, connected, refreshed, logged in or disconnected, and the
  later signals are not sent. Refusing in `before_social_account_create` at
  sign-up rolls back the new user too. Refusing in `before_login` on a first
  sign-in leaves the new user in place; refuse sign-ups in `before_user_create`
  instead, or a Google account before anything is written in `before_callback`.
- **Refusing a provider.** Like every signal, `before_login` gets `provider`, so
  it can stop sign-ins with a provider you no longer accept while leaving users
  and their connections in place:

  ```python
  @receiver(before_login)
  def retired_providers(sender, provider, **kwargs):
      if provider in RETIRED_PROVIDERS:
          raise PermissionDenied("Sign in with your password instead.")
  ```

- **Before the callback is verified** nothing is sent, so `before_callback` and
  the signals after it never see an unverified Google response. A denied
  consent, an expired or replayed callback, another browser's callback, or an
  invalid ID token sends none of them.
- **Return values** are ignored, as for any Django signal. Receivers cannot
  change the email, the user, the Google account or anything else Google
  reported. Put profile fields and application rows in your
  [`CREATE_USER`](#custom-user-models) factory.
- **Errors.** Signals are sent with `send()`, not `send_robust()`, so an
  exception from any receiver propagates. From a signal sent after a commit it
  arrives after the change is saved, which it cannot undo, and the later signals
  of that flow are not sent.
- **Commits.** The signals after a commit are Django
  [`on_commit`](https://docs.djangoproject.com/en/5.2/topics/db/transactions/#performing-actions-after-commit)
  callbacks. Cross Auth's views run outside your transactions, so they follow
  right away.
- **Django's signals.** Cross Auth logs users in with
  `django.contrib.auth.login()`, so Django sends `user_logged_in` itself; Cross
  Auth does not send it again. Password logins send only Django's signals.
  Logging out goes through Django's `LogoutView` and `user_logged_out`; there is
  no Cross Auth logout signal. Provider failures do not emit Django's
  `user_login_failed`, which is sent by failed calls to Django's
  `authenticate()`.

For example, to tell users when Google was connected to their account:

```python
from django.dispatch import receiver

from cross_auth.django.signals import social_account_linked


@receiver(social_account_linked)
def google_connected(sender, social_account, **kwargs):
    print(f"Google connected to user {social_account.user_id}")
```

## Settings reference

All settings live in the `CROSS_AUTH` dictionary. Django's `check` command
reports invalid values.

| Key                         | Default            | Meaning                                                                                                                                            |
| --------------------------- | ------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `PROVIDERS`                 | `[]`               | Provider instances. Only `GoogleProvider` is supported.                                                                                            |
| `CREATE_USER`               | Django's manager   | Dotted path of the user factory for first sign-ins.                                                                                                |
| `PASSWORD_LOGIN`            | `True`             | Whether a usable Django password counts as a way to sign in when disconnecting.                                                                    |
| `REQUIRE_VERIFIED_EMAIL`    | `True`             | Refuse to create users when Google does not report the email as verified.                                                                          |
| `ACCOUNT_LINKING`           | `{}`               | `enabled`: attach a Google sign-in to the user with the same verified email. `allow_different_emails`: see Step 13.                                |
| `BASE_URL`                  | the request's host | Public origin, such as `https://example.com`, used to build the redirect URI.                                                                      |
| `SESSION_ACTIVITY_INTERVAL` | `60`               | Seconds between `last_activity` updates of a [session](#sessions) that nothing else saves. `0` updates it on every request that reads the session. |

`ACCOUNT_LINKING["enabled"]` is off by default. Turning it on lets anyone who
controls a Google account with a matching, verified email sign in to an existing
user, so only enable it if you trust Google's email verification for all of your
users. Even then, Cross Auth refuses when several users share the email.

## How Cross Auth fits into Django

- **CSRF and redirects.** Starting a sign-in, connecting, and disconnecting are
  POSTs checked by `CsrfViewMiddleware`. Google's callback is a cross-site GET,
  which is protected by the single-use state, the browser cookie, PKCE and the
  ID token's nonce instead. The `next` value must be a local path that Django's
  `url_has_allowed_host_and_scheme` accepts; anything else goes to
  `LOGIN_REDIRECT_URL`.
- **Sessions.** Cross Auth requires the `db` or `cached_db` session engine, or
  its own [session engine](#sessions), and saves the session before sending
  `after_login`. Existing session data is kept when an anonymous visitor signs
  in, and Django's usual rules apply to password changes
  (`update_session_auth_hash`) and logout.
- **Inactive users** cannot sign in with Google, and lose their existing
  sessions on the next request.
- **Transactions.** Each step commits on its own. Cross Auth's views opt out of
  `ATOMIC_REQUESTS`, and raise `ImproperlyConfigured` if they run inside another
  transaction, such as one opened by middleware. Users and their Google account
  links live on the database your router picks for the user model.
- **Concurrency.** A database constraint gives each Google account one owner,
  and sign-in state is consumed by exactly one request. When two first sign-ins
  with the same email finish at once, one creates the user and the other shows
  `account_not_linked`; signing in again works. On SQLite, concurrent writes
  wait for each other; consider `"OPTIONS": {"transaction_mode": "IMMEDIATE"}`
  for busy sites, or use PostgreSQL.
- **Errors** render `cross_auth/error.html` with the error code and a
  description. Override the template in your own app to style it.
- **Provider tokens** from Google are not stored. Only the Google account ID,
  its email, and whether Google verified it are kept.

## Multi-factor authentication

Cross Auth's Google sign-in calls `django.contrib.auth.login()` directly. If
your project requires a second factor at sign-in, through `django-otp`,
`django-two-factor-auth`, `django-allauth`'s MFA or your own middleware, Google
sign-in would skip it. Do not enable Cross Auth in such projects yet. Django's
`check` command warns (`cross_auth.W001`) when it finds well-known MFA apps; it
cannot detect every setup.

## Deploying to production

- Serve the site over HTTPS only, set `DEBUG = False`, a secret `SECRET_KEY`,
  and `ALLOWED_HOSTS` to your domain. Run `python manage.py check --deploy`.
- Set `SESSION_COOKIE_SECURE = True` and `CSRF_COOKIE_SECURE = True`. Over
  HTTPS, Cross Auth names its temporary cookie with the `__Host-` prefix and
  marks it `Secure`.
- Register `https://your-domain/auth/google/callback` as an additional redirect
  URI on your Google client, or create a separate production client.
- Behind a proxy that terminates TLS, configure Django to see the original
  scheme and host, for example with `SECURE_PROXY_SSL_HEADER`, only if your
  proxy sets and strips that header. Alternatively set `CROSS_AUTH["BASE_URL"]`
  to your public origin. If your forms post from another origin, list it in
  `CSRF_TRUSTED_ORIGINS`; CORS settings do not replace CSRF protection.
- Keep the Google client secret in your deployment's secret store, not in the
  repository.
- Expired sign-in state is deleted as new state is written. Rows in
  `cross_auth_expiringvalue` are short-lived and safe to clear.

## Troubleshooting

- **`redirect_uri_mismatch` from Google:** the redirect URI Cross Auth sent does
  not exactly match one registered on the client. Compare the `redirect_uri`
  parameter in the address bar on Google's error page with the client's list,
  including `http` versus `https`, `127.0.0.1` versus `localhost`, the port, and
  the missing trailing slash.
- **"OAuth callback belongs to another browser":** the temporary cookie did not
  come back. Start and finish sign-in on the same host: switching between
  `127.0.0.1` and `localhost` causes this, and so does a `BASE_URL` starting
  with `https://` while you browse over plain HTTP.
- **`session_expired` in the URL after sign-in:** the sign-in attempt took more
  than ten minutes or was already used. Start again.
- **`access_denied`:** you cancelled at Google, the account is inactive, or the
  Google account is connected for API access only. With an organization account,
  check the **Audience** settings.
- **403 Forbidden after choosing a Google account:** one of your `before_login`
  or `before_user_create` receivers raised `PermissionDenied`.
- **`invalid_client` or a token exchange error:** check `GOOGLE_CLIENT_ID` and
  `GOOGLE_CLIENT_SECRET`, and that the client type is Web application.
- **`account_not_linked`:** a user with that email already exists. Sign in as
  that user and connect Google from the profile page. Right after a first
  sign-in from two tabs at once, sign in again instead.
- **`KeyError: 'GOOGLE_CLIENT_ID'`:** the environment variables are not set in
  this shell; see Step 8.
- **Django check errors `cross_auth.E00x`:** add the backend, keep database
  sessions, or add the missing middleware, as the message says.
- **Django check warnings `cross_auth.W002` or `cross_auth.W003`:** use
  `SESSION_ENGINE = "cross_auth.django.sessions"` together with
  `cross_auth.django.sessions.SessionMiddleware`; see [Sessions](#sessions).

## Limitations and support

Tested in Cross Auth's CI:

| Area      | Tested                                                     |
| --------- | ---------------------------------------------------------- |
| Python    | 3.11, 3.12, 3.13, 3.14                                     |
| Django    | 5.2 LTS (5.2.8 or later)                                   |
| Databases | SQLite, PostgreSQL 16                                      |
| Users     | `auth.User`; a custom UUID user with its own manager       |
| Sessions  | `db` and `cached_db` engines; `cross_auth.django.sessions` |
| Servers   | Synchronous views under WSGI and ASGI                      |
| Providers | Google, against a mocked Google with real signed ID tokens |

Not supported in this pilot: providers other than Google, Django 6, async views,
sign-in when your project requires multi-factor authentication, sharing one
Google account between several users, and storing Google access or refresh
tokens. Logging out of Django does not sign you out of Google or revoke the
app's access.
