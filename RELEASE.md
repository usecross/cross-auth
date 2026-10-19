---
release type: minor
---

Before hooks can no longer change an identity Cross-Auth has already
established.

Before hooks now receive read-only records instead of the live provider and
stored objects: `ProviderSnapshot` (`id`, `trust_email`), `UserSnapshot` (`id`,
`email`, `email_verified`), and `SocialAccountSnapshot`, exported from
`cross_auth.hooks`. They appear as `provider` in `oauth.authorize`,
`oauth.callback`, `oauth.link`, `oauth.finalize_link`, and `oauth.disconnect`,
as `user` in `oauth.link`, `oauth.finalize_link`, `oauth.disconnect`, and
`token.password`, and as `social_account` in `oauth.disconnect` and
`social_account.update`. `ValidatedUserInfo` is now frozen. Assigning to any of
them raises `dataclasses.FrozenInstanceError`, so a hook can no longer change a
stored user, social account, or provider configuration in place, even if it then
denies the operation. `after` hooks still receive the stored objects.

Returning an event that changes one of the following raises `ValueError` before
anything is resolved or saved:

- the provider, `validated_user_info`, or the raw `id`, `email`, or
  `email_verified` keys of `user_info` in `oauth.callback` and
  `oauth.finalize_link`
- `email`, `email_verified`, or those raw `user_info` keys in `user.create`
- the signed-in user in `oauth.finalize_link`
- `user_id`, `provider`, `provider_user_id`, `is_login_method`,
  `provider_email`, `provider_email_verified`, or those raw `user_info` keys in
  `social_account.create`
- those fields or the `social_account` snapshot in `social_account.update` (they
  were previously ignored)

`oauth.link`, `oauth.disconnect`, and `token.password` still reject any returned
event with `TypeError`.

Hooks can still read these values to deny an operation, and adjust other
`user_info` profile data, provider tokens, `allow_login`, and `extra_fields`.
Canonicalize emails with the `normalize_email` callback instead of a hook. These
rules cover the data passed to hooks; Cross-Auth does not sandbox hook code that
changes global state or writes to storage directly.
