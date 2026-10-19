---
release type: minor
---

Add the storage layer of an optional native Django integration. Install it with
the `django` extra (`cross-auth[django]`, Django 5.2 LTS from 5.2.8) and add
`"cross_auth.django"` to `INSTALLED_APPS`, then run `migrate`.

The app stores provider identities in `cross_auth.SocialAccount`, which
references `settings.AUTH_USER_MODEL`, and short-lived OAuth state in
`cross_auth.ExpiringValue`. `cross_auth.django.storage` implements
`AccountsStorage` and `SecondaryStorage` with the Django ORM:

- A database constraint gives each `(provider, provider_user_id)` one owner.
  Concurrent sign-ups or links of the same identity leave one winner; the others
  roll back and raise `account_already_linked`.
- A first sign-in creates the user, any rows written by its factory, and the
  identity in one `transaction.atomic` block. The default factory supports user
  models managed by Django's `UserManager`, using the email as the username and
  no usable password. Other models set `CROSS_AUTH["CREATE_USER"]` to a dotted
  path.
- Provider emails and their verification flags stay on the identity. Email
  lookups match case-insensitively and reject several matching users.
- Disconnecting serializes per user on SQLite and PostgreSQL and keeps the last
  way to sign in. A usable Django password counts as one unless
  `CROSS_AUTH["PASSWORD_LOGIN"]` is `False`.
- `on_commit` uses `transaction.on_commit(..., robust=False)` on the user
  model's write database; `pop` is a compare-and-delete with one winner.

Provider access and refresh tokens are not stored. Browser views, the
authentication backend, and documentation follow in the next release.
