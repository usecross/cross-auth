---
release type: minor
---

Sessions now record how the user signed in. `SessionRecord.login_method` is
`"password"` or a social provider's id (`"github"`, `"google"`, ...), so a
session list can show "Signed in with GitHub":

| Sign-in                                     | `login_method`                  |
| ------------------------------------------- | ------------------------------- |
| Browser sign-in through `/{provider}/login` | The provider id                 |
| `/token` authorization code grant           | The provider the code came from |
| `/token` password grant (deprecated)        | `"password"`                    |

For sessions your code creates, pass it in `metadata`. It is free-form, so you
can use your own values:

```python
auth.login(str(user.id), response=response, metadata={"login_method": "password"})
token, record = auth.issue_session_token(
    str(user.id), metadata={"login_method": "google"}
)
```

A `login` before hook sees it in `event.metadata["login_method"]` and can
replace it.

The authorization code now carries the provider to `/token`. A custom
`token_issuer` reads it as `TokenIssueRequest.login_method` (`"password"` for
the password grant). Codes issued before the upgrade still redeem, with
`login_method=None`. `AuthorizationCodeGrantData.login_method` holds it.

No migration is required. `login_method` is an optional column for
`SQLModelSessionStorage`: declare `login_method: str | None = None` on your
`SQLModelSession` table and add the column to record it. Tables without it keep
working, the adapter does not write it, and `record.login_method` reads `None`.

Custom `SessionStorage` adapters keep working too: Cross-Auth passes
`login_method` to `create()` only when it accepts that argument (or `**kwargs`).
To record it, accept `login_method: str | None = None` in `create()` and expose
`login_method` on your records. Type checkers flag an adapter against the
`SessionStorage` and `SessionRecord` protocols until it does.
