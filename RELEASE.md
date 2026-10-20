---
release type: minor
---

**Breaking:** the OAuth password grant is deprecated and off by default.
[RFC 9700](https://www.rfc-editor.org/rfc/rfc9700#section-2.4) says the resource
owner password grant MUST NOT be used.

`OAuthServer` now answers `grant_type=password` at `/token` with
`unsupported_grant_type`, before looking up the account, checking a password, or
running hooks. The authorization code grant is unchanged. Clients that still
send password grants need an explicit, temporary opt-in:

```python
auth = CrossAuth(
    ...,
    oauth_server=OAuthServer(get_client=clients.get, password_grant=True),
)
```

With `password_grant=True`, each `grant_type=password` request emits a
`DeprecationWarning`, without the username, password, client or token in the
message. Starting the application, the authorization code grant,
`authenticate()` and your own password sign-in endpoints do not warn.

The grant and the `password_grant` option will be removed in 1.0. Migrate SPA
and native clients to the authorization code grant with PKCE, and first-party
password sign-in to your own endpoint that calls `authenticate()` and then
`login()` or `issue_session_token()`.

The `/token` OpenAPI request schema now inlines its grant schemas, so it
resolves in a plain FastAPI app without merging `router.extra_schemas`. It lists
only the authorization code grant unless `password_grant=True`, which adds a
password variant marked `deprecated`. `router.extra_schemas` still publishes the
models for applications that merge them. If you generate an SDK from OpenAPI,
regenerate and review its types: inlining can change generated request type
names.

`router.issuer.routes` is now a method, `routes(password_grant=...)`, because
the setting lives only on `OAuthServer`.
