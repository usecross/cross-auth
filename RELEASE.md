---
release type: minor
---

Sessions now record how the user signed in, and every `login` hook sees it.

**Breaking:** `SQLModelSession` has a new nullable `login_method` column. Add it
to your session table before deploying, or every session read fails with a
missing-column error. Alembic's autogenerate picks it up; by hand:

```python
op.add_column("usersession", sa.Column("login_method", sa.String(), nullable=True))
```

Existing rows keep `login_method = NULL`.

**Breaking:** Cross-Auth now always passes `login_method: str | None` to
`SessionStorage.create()`. Custom session storages must accept it, store it, and
expose `login_method` on their records (`SessionRecord.login_method`).

**Breaking:** `auth.sign_in_with_id_token()` now also issues the bearer session,
recording the provider as its `login_method`. It takes `max_age` and `metadata`
like `issue_session_token()` and returns `token, session_record, user, created`
(`cross_auth.fastapi.IdTokenSignIn`). Its old behavior, finding or creating the
user without a session, is now `auth.resolve_id_token_user()`.

Before:

```python
user, created = auth.sign_in_with_id_token("apple", id_token, nonce=nonce)
token, record = auth.issue_session_token(str(user.id), metadata={"client_name": "ios"})
```

After:

```python
token, record, user, created = auth.sign_in_with_id_token(
    "apple", id_token, nonce=nonce, metadata={"client_name": "ios"}
)
```

If you mint your own credential, rename the call instead:

```python
user, created = auth.resolve_id_token_user("apple", id_token, nonce=nonce)
```

Like the browser callback, `sign_in_with_id_token()` raises `RuntimeError`
before verifying the token while your accounts storage defers its commits
(inside an application transaction). `resolve_id_token_user()` still works
there; commit before issuing your credential.

`login_method` is `"password"` or a social provider's id (`"github"`,
`"google"`, ...):

| Sign-in                                     | `login_method`                  |
| ------------------------------------------- | ------------------------------- |
| Browser sign-in through `/{provider}/login` | The provider id                 |
| `/token` authorization code grant           | The provider the code came from |
| `/token` password grant (deprecated)        | `"password"`                    |
| `auth.sign_in_with_id_token(provider, ...)` | `provider`                      |

For sessions your code creates, pass it. It is free-form, so you can use your
own values:

```python
auth.login(str(user.id), response=response, login_method="password")
token, record = auth.issue_session_token(str(user.id), login_method="passkey")
```

`BeforeLoginEvent` and `AfterLoginEvent` have a new `login_method` field, set on
every login, including credentials a `token_issuer` mints. A `before` hook can
read it to deny or audit logins by method, or replace it. The approved value is
what the session records, or what the issuer receives as the new
`TokenIssueRequest.login_method`:

```python
@auth.before("login")
def no_password_logins(event: BeforeLoginEvent) -> None:
    if event.login_method == "password":
        raise CrossAuthException("access_denied", "Sign in with GitHub")
```

The authorization code now carries the provider to `/token`
(`AuthorizationCodeGrantData.login_method`). Codes issued before the upgrade
still redeem, with `login_method=None`.
