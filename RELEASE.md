---
release type: minor
---

Authenticated linking with `allow_login: true` can now enable sign-in for an
existing connection after provider verification and ownership checks.
Previously, this option only applied to new connections. Omitting it or setting
it to `false` preserves an existing account's login eligibility. Ordinary
sign-in and connection flows do not enable login for connection-only accounts.

Custom account storage adapters must accept `enable_login: bool = False` in
`update_social_account`. When true, enable login and save credentials
atomically, enforcing one login owner per provider identity. When false, leave
the stored login flag untouched. The SQLModel adapter relies on the required
database ownership constraints and rolls back credential changes when promotion
conflicts with another login owner. Shared schemas must have the unique
login-identity index installed before promotion is used; the adapter does not
validate or install database constraints.
