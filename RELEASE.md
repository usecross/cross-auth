---
release type: minor
---

Run `after` hooks once the storage that owns each write has committed it.
`AccountsStorage` and `SessionStorage` gain a required
`on_commit(callback: CommitCallback) -> None` method (`CommitCallback` is
exported from `cross_auth`). Cross-Auth registers account hooks (`user.create`,
`social_account.*`, `oauth.id_token`, `oauth.finalize_link`, `oauth.disconnect`)
with the accounts storage, and `login`, `logout`, browser `oauth.callback` and
`token.*` hooks with the session storage, or runs them when a custom
`token_issuer` returns. Signup's `user.create` and `social_account.create` hooks
run as one callback, so a failing hook still stops the next one.

Custom storage adapters must add `on_commit`. Adapters whose operations commit
before returning call the callback immediately:

```python
def on_commit(self, callback: CommitCallback) -> None:
    callback()
```

Adapters whose writes join an application transaction run callbacks after the
outermost transaction commits and drop them on rollback. The browser sign-in
flow raises `RuntimeError` rather than issuing a session or authorization code
while account changes are still uncommitted.

The SQLModel adapters commit each operation before returning, so their hooks run
immediately as before. They now raise `RuntimeError` before writing if
`session_factory` returns a session that is already in a transaction or bound to
a connection with an open transaction, because the adapter's commit would not
make the write durable. Return a new `Session(engine)` from the factory.
