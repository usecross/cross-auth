---
release type: minor
---

Session tokens can carry a recognizable prefix and a checksum, like GitHub's
`ghp_` tokens. Set `config["session"]["token_prefix"]`, for example to
`"myapp"`, and every session Cross-Auth issues (cookie logins, `/token`,
`issue_session_token()` and `sign_in_with_id_token()`) gets a token of the form
`myapp_` plus 32 random base62 characters and a 6-character CRC32 checksum. A
leaked token is then easy to spot and can be matched by secret scanners, and a
malformed one can be rejected without a storage lookup. The prefix must be 1 to
16 lowercase letters and digits starting with a letter; anything else raises
`ValueError` when `CrossAuth` or `Context` is created.

Without `token_prefix` nothing changes: tokens are still
`secrets.token_urlsafe(32)`. Lookups still accept any token, so sessions issued
before you set the prefix keep working until they expire.

`identify_token(token)`, on `Context` and on the FastAPI `CrossAuth`, returns
`"session"` when a prefix is configured and the token has that prefix and a
valid checksum, and `None` otherwise. It checks the shape only and does not
authenticate the token. Its return type is exported as `cross_auth.TokenKind`.
