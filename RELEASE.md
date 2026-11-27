---
release type: minor
---

Password checks now upgrade outdated password hashes. With a password hasher
that has `verify_and_update`, as pwdlib's `PasswordHash` and passlib's
`CryptContext` do, `auth.authenticate()` and the OAuth password grant store a
new hash for a matching password whose hash is outdated, so users move to the
hasher's current scheme and settings as they sign in:

```python
from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher
from pwdlib.hashers.bcrypt import BcryptHasher

auth = CrossAuth(
    ...,
    # New hashes use argon2; bcrypt hashes are replaced as users sign in.
    password_hasher=PasswordHash((Argon2Hasher(), BcryptHasher())),
)
```

The accounts storage replaces the hash through a new `replace_password_hash`
method, which the SQLModel adapter has. It writes only if the user still has the
hash that was checked, so a password changed in the meantime keeps its own. A
storage without the method, or a hasher without `verify_and_update`, leaves
hashes as they are. An upgrade that fails never refuses a matching password.

When several instances serve your app, switch schemes in two deploys, as the
Password Hashing docs describe: first a hasher that verifies both schemes but
still hashes with the old one, then the new scheme. Sign-ins now write hashes in
the hasher's preferred scheme, which an instance still on the old hasher cannot
verify.
