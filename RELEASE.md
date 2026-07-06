Release type: minor

New
`CrossAuth.sign_in_with_id_token(provider, id_token, *, user_info=None, nonce=None)`
signs in native/SDK logins — Apple's ASAuthorization, Google's Credential
Manager — by validating the provider id_token against its JWKS and then finding
or creating the user through the same core the web OAuth callback uses:
normalized email lookup, the account-linking policy gate, and the
accounts-storage signup hooks. Apps no longer need to hand-roll the
find-or-create around `validate_id_token` (and silently skip email normalization
and the auto-link safety gate while doing so). `user_info` overlays the token
claims for data providers deliver outside the token, such as Apple's
first-authorization name; `nonce`, when given, must match the token's nonce
claim raw or SHA-256 hashed. Returns `(user, created)`; pair it with
`issue_session_token` for a bearer token. The new `oauth.id_token` before/after
hooks run around the flow, and only `OIDCProvider` subclasses support it —
providers without id_tokens (e.g. GitHub) raise a clear error.
