---
release type: minor
---

Add Sign in with Google for native Django projects. Django keeps owning users,
passwords, permissions, `request.user`, sessions, `login()` and `logout()`;
Cross Auth verifies Google and stores the account links.

Install `cross-auth[django]`, add `"cross_auth.django"` to `INSTALLED_APPS` and
`"cross_auth.django.backends.CrossAuthBackend"` to `AUTHENTICATION_BACKENDS`,
configure providers in `settings.CROSS_AUTH`, and include
`cross_auth.django.urls` (namespace `cross_auth`):

```python
CROSS_AUTH = {
    "PROVIDERS": [
        GoogleProvider(
            client_id=os.environ["GOOGLE_CLIENT_ID"],
            client_secret=os.environ["GOOGLE_CLIENT_SECRET"],
        ),
    ],
}
```

- CSRF-protected POST views start sign-in (`<provider>/login/`) and connect a
  provider to the signed-in user (`<provider>/link/`), and disconnect an account
  without removing the user's last way to sign in. The provider returns to
  `<provider>/callback`, which reuses Cross Auth's state, browser binding, PKCE,
  and nonce checks.
- Sign-in refuses inactive users, existing users with the same email (connect
  explicitly instead), and unverified emails at signup, then calls
  `django.contrib.auth.login()` and saves the database-backed session.
- Django signals in `cross_auth.django.signals` run code around provider
  sign-ins: `before_user_create`, `user_created`, `before_login` and
  `after_login`. Connect receivers with `@receiver` in your app's
  `AppConfig.ready()`. `before_*` receivers get read-only values such as `email`
  and refuse by raising `PermissionDenied` (403); `user_created` and
  `after_login` get the native user and `HttpRequest` once the sign-up or the
  session is committed. Receiver errors propagate and return values are ignored.
  Django's own `user_logged_in` is sent once, by `login()`.
- System checks cover the backend, session engine, middleware and settings, and
  warn when a known multi-factor app is installed, since provider sign-in would
  bypass it.
- When two browsers finish a first sign-in with the same Google account at once,
  one signs in and the other shows `account_not_linked`; signing in again
  reaches the same user.
- A step-by-step guide and `examples/django` show the setup with Google,
  including disconnecting and connecting Google without deleting users.

Core changes shared with FastAPI: browser sign-in can complete through a
framework-owned login instead of a Cross Auth cookie session, the connect flow
can add a login method after the same email checks as `finalize-link`, and
`next` URLs containing backslashes or control characters now fall back to the
default redirect. `LoginCredential` gains `"django_session"`, so code that
matches every credential type needs a new case.
