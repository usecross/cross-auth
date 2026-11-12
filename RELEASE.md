---
release type: minor
---

`CrossAuth` and `AuthRouter` take a `user_can_authenticate` callable that
refuses a user at every point Cross-Auth lets them in: each login, and each use
of a session. It takes the user and returns whether they may sign in, like
Django's `ModelBackend.user_can_authenticate()`:

```python
auth = CrossAuth(
    ...,
    user_can_authenticate=lambda user: user.suspended_at is None,
)
```

When it returns `False`:

- Logins are refused with `403 access_denied` before the `login` hooks run and
  before anything is issued: `auth.login()`, `auth.issue_session_token()`,
  `auth.sign_in_with_id_token()`, browser sign-in and `/token`, including a
  custom `token_issuer`. Browser sign-in checks before it issues an
  authorization code, so an OAuth client gets the error on its redirect.
- `auth.authenticate()` and `auth.resolve_id_token_user()` raise it only once
  the password or token checks out, so nobody learns an account's state without
  its credentials.
- A refused user's session counts as no session: `get_current_user` returns
  `None`, `require_current_user` and the session routes answer 401, and
  `authenticate_session_token` returns `None`. The session is not revoked, and
  is not extended by a sliding refresh. `POST /logout` still works.
- `finalize-link` refuses `allow_login: true`, so a refused user gets no new way
  to sign in.

Raise `CrossAuthException` from it instead to answer with your own error, such
as `CrossAuthException("account_suspended", "Account suspended", 403)`.

Without `user_can_authenticate` every user may sign in, as before. One change
applies either way: `get_current_user` and `authenticate_session_token` now load
the session's user before the sliding refresh, so a session whose user no longer
exists is no longer extended.

Django projects keep Django's own rule: `CrossAuthBackend` refuses users whose
`is_active` is false, at sign-in and on every request.
