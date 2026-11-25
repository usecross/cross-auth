---
release type: minor
---

`user_can_authenticate` can now say why it refuses a user. Return a
`CrossAuthException` instead of `False`, and a sign-in answers with that error
in place of the generic `access_denied` ("Sign-in is not allowed"), while a use
of a session treats it like `False`: the session counts as no session, it is not
extended, and nothing is raised.

```python
from cross_auth.exceptions import CrossAuthException


def user_can_authenticate(user: User) -> bool | CrossAuthException:
    if user.suspended_at is not None:
        return CrossAuthException(
            "account_suspended",
            "This account is suspended. Contact support.",
            status_code=403,
        )
    return True
```

- Every sign-in answers with the returned error as it answers a raised one:
  browser sign-in, connecting and linking with `allow_login`, the OAuth client's
  redirect, `/token` (as a 400 OAuth error), `authenticate()`, `login()`,
  `issue_session_token()`, `sign_in_with_id_token()` and
  `resolve_id_token_user()`.
- Raising a `CrossAuthException` from `user_can_authenticate` works as before:
  it propagates from every check, on each use of a session too.
- Returning any other exception, such as FastAPI's `HTTPException`, raises
  `TypeError` instead of letting the user in.
- A provider sign-in that auto-links a new identity to an existing user found by
  email now checks the user before it attaches the identity, so a refused user
  gains no new way to sign in. The `oauth.id_token` after hooks no longer run
  for a refused user.
- Other `CrossAuthException`s raised while browser sign-in finds or creates the
  user, for example by a `user.create` or `social_account.create` before hook,
  now answer with their own `status_code` instead of always 400.

Apps that suspend or soft-delete accounts should keep those users visible to the
accounts storage and refuse them in `user_can_authenticate`. A SQLModel
`filter_user_query` that hides them breaks sign-in: their provider identity
answers `server_error`, and their email can sign up a second user. The docs no
longer suggest `filter_user_query` for soft deletes. See "Soft-Deleted Users" in
the session authentication guide.
