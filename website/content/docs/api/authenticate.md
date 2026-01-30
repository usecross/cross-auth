---
title: authenticate
description: API reference for the authenticate function.
order: 1
section: API Reference
---

## authenticate()

Verifies an email/password combination against user storage.

```python
from cross_auth import authenticate

user = authenticate(email, password, accounts_storage)
```

### Parameters

| Parameter          | Type              | Description                                  |
| ------------------ | ----------------- | -------------------------------------------- |
| `email`            | `str`             | The user's email address.                    |
| `password`         | `str`             | The plaintext password to verify.            |
| `accounts_storage` | `AccountsStorage` | Storage implementation for looking up users. |

### Returns

| Type           | Description                                                 |
| -------------- | ----------------------------------------------------------- |
| `User \| None` | The user object if credentials are valid, `None` otherwise. |

### Security

This function uses **constant-time password verification**. When a user is not
found, it still runs bcrypt against a dummy hash to prevent timing attacks that
could enumerate valid email addresses.
