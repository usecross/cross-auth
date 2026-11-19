---
release type: minor
---

The Django integration now has the OAuth server: your SPA and native clients can
sign users in with a provider and get a bearer token. It is off until you set
`CROSS_AUTH["OAUTH_SERVER"]`:

```python
CROSS_AUTH = {
    "PROVIDERS": [...],
    "OAUTH_SERVER": {
        # Returns the cross_auth.OAuthClient with a client ID, or None.
        "get_client": "core.clients.get_client",
        # Optional. By default a token lasts a day, however much it is used.
        "token_max_age": 30 * 24 * 60 * 60,
        "token_update_age": 24 * 60 * 60,
    },
}
```

`cross_auth.django.urls` then serves three more views:

- `GET <provider>/authorize` starts a client's sign-in, with PKCE, and ends at
  the client's redirect URI with a one-time code.
- `POST token` exchanges that code for a bearer token.
- `POST logout` revokes the request's bearer token, or every bearer token of its
  user with `{"scope": "all"}`.

Check a token in your API views with
`cross_auth.django.tokens.authenticate_bearer(request)`, which returns the user
and the token's session, or `None`.

Run `migrate` after upgrading. `cross_auth.django.models.Session` gets five
columns: `updated_at`, and `token_hash`, `client_id`, `client_name` and
`revoked_at` for the sessions of bearer tokens, which are kept in that table
through the new `DjangoSessionStorage`. Only a token's hash is stored. The
migration is needed whether or not you use the OAuth server.

With `SESSION_ENGINE = "cross_auth.django.sessions"`:

- `list_sessions` also lists the user's bearer tokens, and `SessionInfo` has two
  new fields, `client_id` and `client_name`, which are `None` for a browser
  session.
- `revoke_session` and `revoke_other_sessions` also revoke bearer tokens. A
  revoked token keeps its row, with `revoked_at` set, until it would have
  expired; a revoked browser session is still deleted.
- `clearsessions` also deletes expired tokens.

The OAuth server does not need that engine. It needs `USE_TZ = True`.

Signals:

- `before_authorization`, `authorization_started` and `before_callback` have a
  third `flow`, `"authorize"`, for a client's sign-in.
- `before_login` and `after_login` are also sent by the token view, when a
  client exchanges its code. A `PermissionDenied` there answers the client with
  `access_denied` as JSON.
- `before_session_revoke` and `session_revoked` are also sent by the logout
  view, with `scope` `"one"` or the new `"all"`.

Not in the Django integration yet: connecting another provider from a signed-in
client, session routes over JSON, and custom token issuers. The deprecated
password grant is not offered.
