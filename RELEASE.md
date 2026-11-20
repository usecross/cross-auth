---
release type: minor
---

The Django integration can now keep the tokens a provider issues at sign-in, as
the SQLModel storage does. It is off by default. Turn it on with
`CROSS_AUTH["PROVIDER_TOKENS"]`, giving the dotted paths of your own `encrypt`
and `decrypt` functions: Cross Auth stores tokens only encrypted, and your
project keeps the key.

```python
CROSS_AUTH = {
    "PROVIDER_TOKENS": {
        "encrypt": "myproject.tokens.encrypt",
        "decrypt": "myproject.tokens.decrypt",
    },
}
```

- `SocialAccount` gains `encrypted_access_token`, `encrypted_refresh_token`,
  `access_token_expires_at`, `refresh_token_expires_at` and `scope`, in
  migration `0004_social_account_tokens`. Run `migrate`.
- `SocialAccount.access_token` and `refresh_token` return the decrypted tokens.
  They return `None` when the setting is off, when nothing is stored, or when
  `decrypt` returns `None`, for example after a key change.
- Each sign-in, and each link of an identity the user already has, replaces its
  tokens, their expiry times and the granted scope.
- With the setting off, a write to an identity clears any tokens it holds.

Cross Auth does not refresh expired tokens; send the user through the link view
for a fresh one. See "Provider tokens" in the Django guide.
