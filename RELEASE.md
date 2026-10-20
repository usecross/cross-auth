---
release type: minor
---

**Breaking:** the OAuth server is now an opt-in component and is off by default.
Update your `CrossAuth` or `AuthRouter` setup before upgrading if you use
`/{provider}/authorize`, `/token`, `/{provider}/link`,
`/{provider}/finalize-link`, `client_redirect_uris`, `get_client`, or
`token_issuer`.

Without `oauth_server`, Cross Auth mounts browser sign-in with a session cookie
(when `config["session"]["cookies"]["auth"]` is enabled), integration-only
`/{provider}/connect`, disconnect, and the provider callback.
`/{provider}/authorize`, `/token`, `/{provider}/link`, and
`/{provider}/finalize-link` are no longer mounted, and the OpenAPI schema lists
only the mounted routes. `sign_in_with_id_token`, `authenticate`, `login`,
`logout`, `issue_session_token` and session management work without the OAuth
server.

To keep those routes, pass an `OAuthServer`. Its options replace the old
top-level arguments:

```python
from cross_auth import OAuthClient, OAuthServer

clients = {
    "web": OAuthClient(
        client_id="web",
        redirect_uris=("https://app.example.com/auth/callback",),
    ),
}

auth = CrossAuth(
    ...,
    oauth_server=OAuthServer(
        get_client=clients.get,
        token_issuer=issue_token,  # optional
    ),
)
```

Migration from 0.38:

- `config["client_redirect_uris"]` is removed. Register each client as an
  `OAuthClient` and pass a lookup such as `clients.get` to
  `OAuthServer(get_client=...)`. Unknown `config` keys, including
  `client_redirect_uris` and `allowed_client_ids`, now raise `ValueError`.
- `get_client=` and `token_issuer=` move from `CrossAuth`, `AuthRouter` and
  `Context` into `OAuthServer`. Passing them at the top level raises
  `TypeError`. A database-backed `get_client` works unchanged.
- `OAuthServer()` without `get_client` rejects every client.
- `AuthRouter` takes `providers`, `secondary_storage`, `accounts_storage` and
  `get_user_from_request` positionally; every other argument is keyword-only.
  `Context` takes every argument after `session_storage` by keyword.
- `Context.token_issuer` is replaced by `Context.oauth_server`.

`OAuthServer` keeps the redirect policy: `get_client` is called on every
request, a returned client with a different `client_id` is an error, and
registrations are checked again at the provider callback, `/token` and
`/finalize-link`.

Authorization and link attempts started before the OAuth server was removed are
refused at the provider callback with `invalid_request`, after the browser and
state checks and without contacting the provider, changing accounts, or
redirecting to the client.
