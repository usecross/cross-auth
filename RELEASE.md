---
release type: minor
---

Cross Auth now exposes typed `user.create`, `social_account.create`, and
`social_account.update` lifecycle events through the existing `CrossAuth.before`
and `CrossAuth.after` hook system. Before hooks can enforce signup policy,
customize writable account fields, and provide app-specific `extra_fields`;
after hooks can observe committed account changes. The hooks run consistently
across browser OAuth, native ID-token sign-in, connect, and finalize-link flows.

The built-in SQLModel account storage validates and writes mapped extra fields,
supports writable `email_verified` aliases, and keeps transaction ownership in
`create_user`. Apps that need related rows in that transaction can override the
private `_build_user` escape hatch. Tokenless social-account models can omit the
five credential columns by listing them in `excluded_social_account_fields`,
while still exposing readable properties for the credential values required by
the core account protocol.

This release replaces the SQLModel-specific `on_signup`, `after_signup`,
`build_user`, `build_social_account_create_values`, and
`build_social_account_update_values` extension methods. Custom `AccountsStorage`
implementations must also accept the optional `extra_fields` argument on user
and social-account writes.

`RedisStorage.from_url()` now creates and owns a reusable redis-py client.
Applications should call `close()` during shutdown; clients passed directly to
`RedisStorage(...)` remain caller-owned.
