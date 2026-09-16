---
release type: patch
---

Native ID-token sign-in now derives authentication identity exclusively from
verified provider claims. Caller-supplied `user_info`, including metadata
returned by `oauth.id_token` before hooks, accepts only `name`, `first_name`,
`last_name`, and `picture`; all other keys are ignored. Applications that
previously passed custom fields through this parameter should move that mapping
to trusted account creation hooks. Provider claim mapping remains customizable
through `extract_user_info_from_claims` and `validate_user_info`.
