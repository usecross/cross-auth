---
release type: minor
---

Two password sign-ins for your own sign-in endpoint check an email and password
and sign the user in. `auth.sign_in_with_password()` issues a bearer session and
returns the token, the session record and the user. `auth.login_with_password()`
sets the session cookie on `response` and returns the user. Both return `None`
for a wrong email or password:

```python
signed_in = auth.sign_in_with_password(email, password, metadata={"client_name": "CLI"})
if signed_in is None:
    raise HTTPException(status_code=401, detail="Invalid credentials")

return {"access_token": signed_in.token}
```

```python
user = auth.login_with_password(email, password, response=response)
if user is None:
    raise HTTPException(status_code=401, detail="Invalid credentials")
```

Unlike `auth.authenticate()` followed by `auth.issue_session_token()` or
`auth.login()`, they check the password again once the session is stored. A
password change stores the new hash, then revokes the user's sessions. A sign-in
that checked the old password just before the change, and stored its session
just after the revocation, kept a session the change meant to end. Now that
sign-in is refused as for a wrong password, its session is revoked, and no
cookie is set. A hash that changed while the password still matches it, such as
the same password stored with a new salt, still signs in.

The deprecated `/token` password grant checks again too, and answers such a
sign-in with `invalid_grant`. With a `token_issuer`, the minted token is not
handed out.

All of them rely on a password change storing the new hash before it revokes the
user's sessions, as `change_password()` does.
