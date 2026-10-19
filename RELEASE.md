---
release type: minor
---

Before hooks can no longer change an identity Cross-Auth has already
established. The following now raise `ValueError` before anything is resolved or
saved, whether the hook mutates the event in place or returns a replacement:

- changing the provider or `validated_user_info.provider_user_id` in
  `oauth.callback` and `oauth.finalize_link`
- changing the signed-in user in `oauth.link`, `oauth.finalize_link`, and
  `token.password`
- changing `user_id`, `provider`, `provider_user_id`, or `is_login_method` in
  `social_account.create`
- changing those fields or the existing `social_account` in
  `social_account.update` (they were previously ignored)

Hooks can still deny these operations and adjust provider claim data, provider
tokens, `allow_login`, and `extra_fields`.
