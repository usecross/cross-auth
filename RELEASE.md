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

`login_method` is `"password"` or a social provider's id (`"github"`,
`"google"`, ...):

| Sign-in                                     | `login_method`                  |
| ------------------------------------------- | ------------------------------- |
| Browser sign-in through `/{provider}/login` | The provider id                 |
| `/token` authorization code grant           | The provider the code came from |
| `/token` password grant (deprecated)        | `"password"`                    |
| `auth.exchange_id_token(provider, ...)`     | `provider`                      |

For sessions your code creates, pass it. It is free-form, so you can use your
own values:

```python
auth.login(str(user.id), response=response, login_method="password")
token, record = auth.issue_session_token(str(user.id), login_method="passkey")
```

The new `auth.exchange_id_token()` signs a native app in with a provider
`id_token` and issues its bearer session in one call, recording the provider. It
takes the arguments of `sign_in_with_id_token()` plus `max_age` and `metadata`,
and returns `token, session_record, user, created`:

```python
token, record, user, created = auth.exchange_id_token("apple", id_token, nonce=nonce)
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

With `cross_auth.django`, a provider sign-in stores the provider in Django's
session: `cross_auth.django.get_login_method(request)` returns it, or `None` for
other logins such as Django's password login.
