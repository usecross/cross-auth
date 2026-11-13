---
release type: minor
---

`auth.change_password()` changes the signed-in user's password and signs their
other devices out, so a stolen session no longer outlives the password change a
user makes to lock an attacker out:

```python
@app.post("/change-password")
def change_password(request: Request, body: PasswordChange):
    auth.change_password(
        request,
        current_password=body.current_password,
        new_password=body.new_password,
    )
    return {"ok": True}
```

- It changes the password of the user the request's session signs in, and raises
  `CrossAuthException("unauthorized")` (401) without one.
- `current_password` must match, or it raises `invalid_password` (400) and
  changes nothing. It is `None` only for a user without a password, such as one
  who signed up with a provider and sets a first password.
- The accounts storage hashes and stores the new password. The SQLModel storage
  stores a bcrypt hash and refuses a password longer than bcrypt's 72 bytes with
  `password_too_long` (400).
- Then it revokes the user's other sessions through the `session.revoke` hooks,
  with `scope="others"`, and keeps the request's session signed in. Pass
  `revoke_other_sessions=False` to keep them all.

A password set any other way, such as from a reset link, signs no one out; call
`auth.revoke_all_sessions(user_id=...)` when it should.

`change_password` needs an accounts storage with a
`set_password(user_id, password)` method, which stores the password and returns
the updated user, or `None` when the user is not found. The SQLModel storage has
one, using the new `cross_auth._password.hash_password`; other accounts storages
need not add it unless they use `change_password`, which raises `TypeError`
without it. The Django storage has none: Django projects keep using Django's
password views.
