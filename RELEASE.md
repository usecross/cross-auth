---
release type: minor
---

Before hooks can no longer change an identity Cross-Auth has already
established. The following now raise `ValueError` before anything is resolved or
saved, whether the hook mutates the event in place or returns a replacement:

- changing the provider or `validated_user_info.provider_user_id`, `email`, or
  `email_verified` in `oauth.callback` and `oauth.finalize_link`
- changing `email` or `email_verified` in `user.create`
- changing the signed-in user in `oauth.link`, `oauth.finalize_link`, and
  `token.password`
- changing `user_id`, `provider`, `provider_user_id`, `is_login_method`,
  `provider_email`, or `provider_email_verified` in `social_account.create`
- changing those fields or the existing `social_account` in
  `social_account.update` (they were previously ignored)

Hooks can still read these claims to deny an operation, and adjust raw
`user_info` profile data, provider tokens, `allow_login`, and `extra_fields`.
Canonicalize emails with the `normalize_email` callback instead of a hook.
