---
release type: minor
---

Cross-Auth can now verify and hash passwords with any password hasher, not only
bcrypt, so apps that store argon2 or other hashes can use `auth.authenticate()`,
`auth.change_password()` and the password grant. Pass `password_hasher` to
`CrossAuth`, or to `AuthRouter`:

```python
from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher
from pwdlib.hashers.bcrypt import BcryptHasher

auth = CrossAuth(
    providers=providers,
    storage=storage,
    accounts_storage=accounts_storage,
    session_storage=session_storage,
    # New hashes are argon2; the bcrypt hashes users have keep verifying.
    password_hasher=PasswordHash((Argon2Hasher(), BcryptHasher())),
)
```

- A hasher has `hash(password) -> str` and `verify(password, hash) -> bool`, the
  new `cross_auth.PasswordHasher` protocol. pwdlib's `PasswordHash` and
  passlib's `CryptContext` fit as they are.
- The default, the new `cross_auth.BcryptPasswordHasher`, behaves as before: it
  verifies the first 72 bytes of a password and refuses to hash a longer one
  with `password_too_long`.
- A stored hash the hasher can't read never matches: whatever `verify` raises
  counts as a wrong password, and Cross-Auth logs the error's type on the
  `cross_auth._password` logger. Unknown users, users without a password and
  users whose hash can't be read each verify a dummy hash, which the hasher
  makes once, so they take as long as anyone else.
- `auth.password_hasher` is the hasher in use. Hash the passwords you store
  yourself, such as at signup, with `auth.password_hasher.hash(password)`.
- `cross_auth._password.authenticate()` takes `password_hasher=` too.

`PasswordStorage.set_password` now receives the hasher as a required keyword,
`set_password(user_id, password, *, password_hasher)`, and stores
`password_hasher.hash(password)`. `change_password` passes its own, so the hash
it stores is always one its checks read. Custom accounts storages with a
`set_password` method need the new parameter; without it `change_password`
raises `TypeError`. Code that calls the SQLModel storage's `set_password` itself
passes `password_hasher=auth.password_hasher`.
