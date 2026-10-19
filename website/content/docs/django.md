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
- sign in with a Django password, then connect Google to the same user;
- disconnect Google without losing their last way to sign in;
- sign out with Django's own logout.

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

- Python 3.11 or later and [uv](https://docs.astral.sh/uv/).
- A Google account that can create a project in the
  [Google Cloud console](https://console.cloud.google.com/).

## Step 1: Create the project

Create an empty project and install Cross Auth with its `django` extra, which
also installs Django 5.2:

```bash
mkdir django-google-demo
cd django-google-demo
uv init --bare
uv add "cross-auth[django]"
```

> **Note:** the Django integration was added after Cross Auth 0.36.0. Until a
> release that includes it is on PyPI, install it from GitHub instead:
> `uv add "cross-auth[django] @ git+https://github.com/usecross/cross-auth@2026-10-20-django-google-login"`.

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
    "core",
]
```

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
4. It called `django.contrib.auth.login()`, which rotated the session key and
   stored the session through Django's session backend.

Your browser now holds Django's `sessionid` and `csrftoken` cookies and nothing
else. Open [http://127.0.0.1:8000/profile/](http://127.0.0.1:8000/profile/) in a
new tab; `@login_required` and `request.user` work as with any Django login.

Click **Sign out**. Django's `LogoutView` ends the session. You are still signed
in to Google itself, so the next sign-in may skip Google's account chooser.

## Step 10: Connect Google to a password account

People who already have a Django account should sign in the way they always did,
then connect Google. Cross Auth never attaches a Google account to an existing
user just because the email addresses match: signing in with Google as
`you@gmail.com` while a user with that email exists shows an
`account_not_linked` error instead.

Create a user with a password and the same email as your Google account,
replacing `you@gmail.com`. The first command deletes the user Step 9 created,
whose username is that email, together with its Google connection:

```bash
uv run python manage.py shell -c "
from django.contrib.auth.models import User
User.objects.filter(username='you@gmail.com').delete()
User.objects.create_user('alice', 'you@gmail.com', 'a-long-unique-password')
"
```

1. Sign in at
   [http://127.0.0.1:8000/accounts/login/](http://127.0.0.1:8000/accounts/login/)
   as `alice`.
2. On your profile, click **Connect Google** and pick the Google account for
   `you@gmail.com`.
3. Back on the profile, Google is listed under **Connected accounts**.
4. Sign out, then click **Sign in with Google** on the home page. You are signed
   in as `alice`.

Connecting requires Google to report the email as verified and to match the
user's email, ignoring case. To let people connect a Google account with a
different email, set `"ACCOUNT_LINKING": {"allow_different_emails": True}` in
`CROSS_AUTH`. A Google account can belong to only one user; connecting one that
another user already has fails with `account_already_linked`.

## Step 11: Disconnect safely

While signed in as `alice`, click **Disconnect** next to Google. Alice still has
a password, so the Google account is removed and she can only sign in with her
password again.

Now sign in with Google as a user who signed up through Google (as in Step 9)
and click **Disconnect**. Cross Auth refuses with `no_alternative_login_method`,
because the user would have no way left to sign in. If your site has no password
sign-in, set `"PASSWORD_LOGIN": False` so that a usable password does not count
as an alternative.

## Step 12 (optional): Run code around sign-in

Cross Auth's [hooks](/docs/hooks) run around sign-in. `login` hooks wrap every
Google sign-in: a `before` hook can refuse it by raising `CrossAuthException`,
and an `after` hook runs once the Django session is saved. Create
`core/auth_hooks.py`:

```python
from cross_auth.exceptions import CrossAuthException
from cross_auth.hooks import AfterUserCreateEvent, BeforeLoginEvent, HookRegistry

hooks = HookRegistry()


def only_company_accounts(event: BeforeLoginEvent) -> None:
    from django.contrib.auth import get_user_model

    user = get_user_model()._default_manager.get(pk=event.user_id)
    if not user.email.endswith("@example.com"):
        raise CrossAuthException(
            "access_denied", "Use your company account.", status_code=403
        )


def welcome(event: AfterUserCreateEvent) -> None:
    print(f"New user {event.user.id}")


hooks.register_before("login", only_company_accounts)
hooks.register_after("user.create", welcome)
```

Then point `CROSS_AUTH` at it:

```python
CROSS_AUTH = {
    "PROVIDERS": [...],
    "HOOKS": "core.auth_hooks.hooks",
}
```

`login` events for Django sign-ins have `credential="django_session"`. Hooks run
only for Google sign-ins; Django's own password login does not run them.

On a first sign-in, the user and its Google connection are created before the
`login` hooks run, so a refused login leaves the new user in place. To stop
sign-ups instead, raise from a `before` `user.create` hook.

## Custom user models

Cross Auth creates users with your user model's default manager. The default
factory works with models managed by Django's `UserManager`, including
`AbstractUser` subclasses: it uses the email as username, sets no usable
password, and passes any `extra_fields` from `user.create` hooks.

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
not call external services from it; use an `after` `user.create` hook, which
runs after the transaction commits. Custom primary keys, such as UUIDs, are
supported.

## Settings reference

All settings live in the `CROSS_AUTH` dictionary. Django's `check` command
reports invalid values.

| Key                      | Default            | Meaning                                                                                                             |
| ------------------------ | ------------------ | ------------------------------------------------------------------------------------------------------------------- |
| `PROVIDERS`              | `[]`               | Provider instances. Only `GoogleProvider` is supported.                                                             |
| `CREATE_USER`            | Django's manager   | Dotted path of the user factory for first sign-ins.                                                                 |
| `PASSWORD_LOGIN`         | `True`             | Whether a usable Django password counts as a way to sign in when disconnecting.                                     |
| `REQUIRE_VERIFIED_EMAIL` | `True`             | Refuse to create users when Google does not report the email as verified.                                           |
| `ACCOUNT_LINKING`        | `{}`               | `enabled`: attach a Google sign-in to the user with the same verified email. `allow_different_emails`: see Step 10. |
| `HOOKS`                  | none               | Dotted path of a `HookRegistry`.                                                                                    |
| `BASE_URL`               | the request's host | Public origin, such as `https://example.com`, used to build the redirect URI.                                       |

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
- **Sessions.** Cross Auth requires the `db` or `cached_db` session engine, and
  saves the session before `after` `login` hooks run. Existing session data is
  kept when an anonymous visitor signs in, and Django's usual rules apply to
  password changes (`update_session_auth_hash`) and logout.
- **Inactive users** cannot sign in with Google, and lose their existing
  sessions on the next request.
- **Transactions.** Each step commits on its own. Cross Auth's views opt out of
  `ATOMIC_REQUESTS`, and raise `ImproperlyConfigured` if they run inside another
  transaction, such as one opened by middleware. Users and their Google account
  links live on the database your router picks for the user model.
- **Concurrency.** A database constraint gives each Google account one owner,
  and sign-in state is consumed by exactly one request. On SQLite, concurrent
  writes wait for each other; consider
  `"OPTIONS": {"transaction_mode": "IMMEDIATE"}` for busy sites, or use
  PostgreSQL.
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
- **`access_denied`:** you cancelled at Google, the account is inactive, a
  `before` hook refused it, or the Google account is connected for API access
  only. With an organization account, check the **Audience** settings.
- **`invalid_client` or a token exchange error:** check `GOOGLE_CLIENT_ID` and
  `GOOGLE_CLIENT_SECRET`, and that the client type is Web application.
- **`account_not_linked`:** a user with that email already exists. Sign in as
  that user and connect Google from the profile page.
- **`KeyError: 'GOOGLE_CLIENT_ID'`:** the environment variables are not set in
  this shell; see Step 8.
- **Django check errors `cross_auth.E00x`:** add the backend, keep database
  sessions, or add the missing middleware, as the message says.

## Limitations and support

Tested in Cross Auth's CI:

| Area      | Tested                                                     |
| --------- | ---------------------------------------------------------- |
| Python    | 3.11, 3.12, 3.13, 3.14                                     |
| Django    | 5.2 LTS (5.2.8 or later)                                   |
| Databases | SQLite, PostgreSQL 16                                      |
| Users     | `auth.User`; a custom UUID user with its own manager       |
| Sessions  | `db` and `cached_db` engines                               |
| Servers   | Synchronous views under WSGI and ASGI                      |
| Providers | Google, against a mocked Google with real signed ID tokens |

Not supported in this pilot: providers other than Google, Django 6, async views,
sign-in when your project requires multi-factor authentication, listing or
revoking a user's sessions across devices, sharing one Google account between
several users, and storing Google access or refresh tokens. Logging out of
Django does not sign you out of Google or revoke the app's access.
