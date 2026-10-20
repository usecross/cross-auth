---
release type: minor
---

Make the OAuth server optional. `CrossAuth(..., oauth_server=False)` and
`AuthRouter(..., oauth_server=False)` keep browser sign-in with a session
cookie, integration-only `/{provider}/connect`, disconnect, and the provider
callback, without mounting the routes that make Cross Auth an authorization
server for SPA and native clients: `/{provider}/authorize`, `/token`,
`/{provider}/link`, and `/{provider}/finalize-link`. The OpenAPI schema lists
only the mounted routes.

```python
auth = CrossAuth(
    providers=[google],
    storage=secondary_storage,
    accounts_storage=accounts_storage,
    session_storage=session_storage,
    config={"session": {"cookies": {"auth": True}}},
    oauth_server=False,
)
```

The OAuth server stays enabled by default, so existing applications keep every
route and need no migration. `client_redirect_uris`, `get_client`, and
`token_issuer` configure the OAuth server and raise `ValueError` with
`oauth_server=False`. Cookie sign-in still requires `session_storage` and
`config["session"]["cookies"]["auth"]`.

Authorization and link attempts started before the OAuth server was turned off
are refused at the provider callback with `invalid_request`, without contacting
the provider, changing accounts, or redirecting to the client.
`sign_in_with_id_token`, `issue_session_token`, `authenticate`, `login`,
`logout`, and session management work the same with or without the OAuth server.
