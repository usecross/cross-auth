---
title: authenticate
description: API reference for the authenticate function.
order: 1
section: API Reference
---

## authenticate()

Verifies an email/password combination against user storage.

```python
from cross_auth._password import authenticate

user = authenticate(email, password, accounts_storage)
```

### Parameters

| Parameter          | Type              | Description                                                                                                                      |
| ------------------ | ----------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `email`            | `str`             | The user's email address.                                                                                                        |
| `password`         | `str`             | The plaintext password to verify.                                                                                                |
| `accounts_storage` | `AccountsStorage` | Storage implementation for looking up users.                                                                                     |
| `password_hasher`  | `PasswordHasher`  | Keyword-only. Verifies the stored hash; defaults to `BcryptPasswordHasher`. Pass the one you give `CrossAuth(password_hasher=)`. |

### Returns

| Type           | Description                                                 |
| -------------- | ----------------------------------------------------------- |
| `User \| None` | The user object if credentials are valid, `None` otherwise. |

### Security

This function uses **constant-time password verification**. When a user is not
found, has no password or has a hash the hasher can't read, it still verifies a
dummy hash made by the same hasher, to prevent timing attacks that could
enumerate valid email addresses. A hash the hasher can't read never matches:
whatever `verify` raises counts as a wrong password. See
[Password Hashing](/docs/session-authentication#password-hashing).
