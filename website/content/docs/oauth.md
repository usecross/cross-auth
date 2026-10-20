---
title: OAuth 2.0
description: OAuth 2.0 authorization code flow with PKCE support.
order: 3
section: Guides
---

## Overview

Cross-Auth implements the OAuth 2.0 authorization code flow with PKCE (Proof Key
for Code Exchange). This is used when Cross-Auth acts as the authorization
server -- for example, when your SPA or mobile app needs to obtain tokens.

## The OAuth server

The OAuth server is the part of Cross-Auth that acts as an authorization server
for your own registered clients. It adds these routes:

- `GET /{provider}/authorize`, which signs a client in through the provider and
  redirects back to the client with a Cross-Auth authorization code;
- `POST /token`, which exchanges that code (with the client's PKCE verifier) for
  a bearer token;
- `POST /{provider}/link` and `POST /{provider}/finalize-link`, the PKCE account
  linking flow for clients that authenticate with a bearer token.

The OAuth server is not how Cross-Auth talks to Google or GitHub. Signing in
with a provider in the browser, the provider callback, its PKCE, `state` and
nonce checks all work without it. Neither does every bearer token come from the
OAuth server: `issue_session_token` mints the same revocable token for your own
sign-in endpoints. The OAuth server serves public clients you register (SPAs and
native apps); it is not a general identity provider for third-party apps and has
no consent screens or confidential-client authentication.

The OAuth server is off by default. Applications whose browsers sign in with a
session cookie don't need it:

```python
auth = CrossAuth(
    providers=providers,
    storage=secondary_storage,
    accounts_storage=accounts_storage,
    session_storage=session_storage,
    config={"session": {"cookies": {"auth": True}}},
)
```

Without the OAuth server, Cross-Auth mounts `GET /{provider}/login` (when cookie
sign-in is enabled), `GET /{provider}/connect`, the
`DELETE /{provider}/social-accounts` routes, and
`GET`/`POST /{provider}/callback`; the OpenAPI schema lists only those. Leaving
the OAuth server out does not turn cookie sign-in on: `/{provider}/login` still
needs `session_storage` and `config["session"]["cookies"]["auth"]`.

`/{provider}/connect` remains integration-only: it does not enable that identity
for sign-in. Adding another identity as a login method uses the OAuth server's
`link`/`finalize-link` flow.

To serve a SPA or native app, pass an `OAuthServer`. It holds every OAuth server
option, and `AuthRouter` takes the same keyword-only `oauth_server`:

```python
from cross_auth import OAuthClient, OAuthServer
from cross_auth.fastapi import CrossAuth

clients = {
    "web-app": OAuthClient(
        client_id="web-app",
        redirect_uris=("https://app.example.com/callback",),
    ),
}

auth = CrossAuth(
    providers=providers,
    storage=secondary_storage,
    accounts_storage=accounts_storage,
    session_storage=session_storage,
    config={"session": {"cookies": {"auth": True}}},
    oauth_server=OAuthServer(get_client=clients.get),
)
```

- `get_client` controls client registration for authorization-code and linking
  flows; see [Register clients](#register-clients). Without it, those flows
  reject every client. The legacy password grant does not use this lookup.
- `token_issuer` mints the token `/token` returns; see
  [Custom token issuers](#custom-token-issuers). Without it, `/token` issues an
  opaque session token from `session_storage`.

The provider callback also completes session and connect flows, so it stays
mounted without the OAuth server. Authorization and link attempts started before
the OAuth server was removed are refused there with `invalid_request`: after the
browser binding check consumes the attempt, Cross-Auth returns an error without
contacting the provider, creating or linking accounts, storing a code, or
redirecting to the client. Users start again from the client.

## Register clients

`OAuthClient` describes one application receiving tokens from Cross-Auth. Its
client ID is separate from your Google/GitHub provider credentials. A dashboard
and mobile application can have different client IDs while authenticating the
same users.

`OAuthServer(get_client=...)` takes a lookup with the signature
`get_client(client_id: str) -> OAuthClient | None`. For hardcoded clients, a
dictionary's `.get` is enough:

```python
from cross_auth import OAuthClient, OAuthServer

clients = {
    "cloud-dashboard": OAuthClient(
        client_id="cloud-dashboard",
        redirect_uris=(
            "https://dashboard.example.com/callback",
            "https://dashboard.example.com/link-callback",
        ),
    ),
    "cloud-mobile": OAuthClient(
        client_id="cloud-mobile",
        application_type="native",
        redirect_uris=("com.example.cloud:/callback",),
    ),
}

oauth_server = OAuthServer(get_client=clients.get)
```

`/{provider}/authorize` and `/{provider}/link` require a registered `client_id`
and a matching `redirect_uri`. A client registered for one callback cannot use
another client's callback. To combine hardcoded and database clients, implement
that precedence in your lookup.

Matching uses the complete original URL string, including scheme, host, port,
path, query string, and case. Register each intended variation explicitly:
`http://localhost:5173/callback` does not match
`http://127.0.0.1:5173/callback`, a trailing slash, or an added query parameter.
Web clients (the default `application_type`) support HTTP and HTTPS URLs. Use
HTTPS in production. Fragments, user information, backslashes, whitespace, and
hostname wildcards are rejected. Register ASCII URI spelling: percent-encode
non-ASCII paths/query values and use punycode for international hostnames.

These are the application's callbacks, separate from the provider callback such
as `/auth/github/callback` that Cross-Auth handles itself. A SPA using
`${window.location.origin}/callback` must register that full URL for each
environment where it runs.

### Database-backed clients

The callback has the signature
`get_client(client_id: str) -> OAuthClient | None`. It is synchronous, may query
any datastore, and returns `None` for unknown or disabled apps. The returned
`client_id` must match the requested one.

For example, with an application-owned SQLModel `OAuthApplication` whose primary
key is `client_id` and which stores `redirect_uris`, `application_type`, and an
`enabled` flag:

```python
from sqlmodel import Session

from cross_auth import OAuthClient


def get_client(client_id: str) -> OAuthClient | None:
    with Session(engine) as session:
        application = session.get(OAuthApplication, client_id)
        if application is None or not application.enabled:
            return None

        return OAuthClient(
            client_id=application.client_id,
            redirect_uris=tuple(application.redirect_uris),
            application_type=application.application_type,
        )
```

Pass this function as `OAuthServer(get_client=get_client)`. Django can supply
the same record from an ORM query. Cross-Auth does not require a client table,
schema migration, or storage adapter; the application owns registration and
app-management APIs. Registration data is validated when the `OAuthClient` is
constructed.

Cross-Auth does not cache callback results: it looks up the registration again
at provider callback completion and code redemption. Changes therefore affect
pending attempts without recreating `CrossAuth`. Already issued sessions are
managed separately; disabling a client does not revoke its existing sessions. A
lookup failure propagates instead of falling back to another registration.

### Native applications

Set `application_type="native"` for a native app. Supported redirects follow
[RFC 8252](https://www.rfc-editor.org/rfc/rfc8252.html#section-7):

- Claimed HTTPS URLs, matched exactly. Configure the OS association with your
  app.
- Reverse-domain private-use schemes such as `com.example.cloud:/callback`,
  matched exactly. The URI must have no authority and begin its path with `/`.
- HTTP loopback URLs using literal `127.0.0.1` or `[::1]`. Only the port may
  vary; the host, path, and query must still match the registration. Register
  `http://127.0.0.1/callback` to allow an OS-assigned listening port.
  `localhost` and alternative IP spellings are not supported for native loopback
  redirects.

Use the system browser and retain its binding cookie through the provider
callback. The native app then receives Cross-Auth's authorization code and
exchanges it with its original PKCE verifier. `/token` requires the exact
redirect URI used for that attempt, including the selected loopback port. No
client secret is required for this public-client flow.

The lookup API covers the existing authorization-code and linking flows. It does
not add confidential-client authentication, consent screens, delegated scope
policy, or public dynamic-registration endpoints. Those need explicit
application policy before opening registration to arbitrary third-party apps.
The legacy password grant is separate and does not use this client lookup.

### Migrate from 0.38

Cross-Auth 0.38 enabled the OAuth server by default and configured it with
top-level settings. Update your setup before upgrading:

```python
# 0.38
auth = CrossAuth(
    ...,
    config={
        "client_redirect_uris": {"web-app": ["https://app.example.com/callback"]},
        "session": {"cookies": {"auth": True}},
    },
    token_issuer=issue_token,
)

# Now
clients = {
    "web-app": OAuthClient(
        client_id="web-app",
        redirect_uris=("https://app.example.com/callback",),
    ),
}

auth = CrossAuth(
    ...,
    config={"session": {"cookies": {"auth": True}}},
    oauth_server=OAuthServer(get_client=clients.get, token_issuer=issue_token),
)
```

- Turn each `config["client_redirect_uris"]` entry into an `OAuthClient`.
  Unknown `config` keys, including `client_redirect_uris` and the older
  `allowed_client_ids`, raise `ValueError` at startup.
- Move `get_client=` and `token_issuer=` into `OAuthServer`. Passing them to
  `CrossAuth` or `AuthRouter` raises `TypeError`.
- Applications that never used `/authorize`, `/token`, `/link` or
  `/finalize-link` need no `OAuthServer`.
- Clients that still send `grant_type=password` to `/token` need
  `OAuthServer(password_grant=True)` until they migrate; see
  [Password Grant](#password-grant-deprecated).

Client redirect registration does not configure CORS or CSRF protection;
configure those separately in the hosting application. Relative `next`
destinations in the session `/login` and `/connect` flows are unaffected by
client redirect registration.

## Supported Grant Types

### Authorization Code Grant (with PKCE)

The recommended flow for public clients (SPAs, mobile apps):

1. Client generates a `code_verifier` and derives a `code_challenge` (S256).
2. Client redirects the user to the authorization endpoint with the
   `code_challenge`.
3. User authenticates and authorizes the request.
4. Server returns an authorization code to the client's redirect URI.
5. Client exchanges the code + `code_verifier` for an access token at the token
   endpoint.

The token endpoint issues opaque bearer tokens backed by `SessionStorage`. These
tokens are revocable session records, not JWTs. Configure `session_storage` on
`CrossAuth` to enable token issuance; without it or a `token_issuer`, `/token`
returns an OAuth error instead of minting a token.

### Custom token issuers

`OAuthServer(token_issuer=...)` replaces the session token with your own
credential, such as a JWT. It receives a `TokenIssueRequest` with the user,
client, grant type and scope, and returns the token and its lifetime in seconds:

```python
from cross_auth import OAuthServer, TokenIssueRequest


def issue_token(request: TokenIssueRequest) -> tuple[str, int]:
    return mint_jwt(subject=request.user_id, audience=request.client_id), 900


oauth_server = OAuthServer(get_client=clients.get, token_issuer=issue_token)
```

The `login` hooks run around the call; Cross-Auth creates no session for it.

### Password Grant (deprecated)

The resource owner password grant is deprecated and will be removed in
Cross-Auth 1.0. [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700#section-2.4),
the OAuth 2.0 Security Best Current Practice, says it MUST NOT be used: it hands
the user's password to the client, and it cannot support multi-factor or passkey
sign-in.

`OAuthServer` refuses it by default: `/token` answers `grant_type=password` with
`unsupported_grant_type` before looking up the account, verifying a password or
running hooks, and its OpenAPI schema lists only the authorization code grant.
Without the OAuth server there is no `/token` endpoint at all.

Clients that still need it can opt in while they migrate:

```python
oauth_server = OAuthServer(
    get_client=clients.get,
    # Deprecated; removed in 1.0.
    password_grant=True,
)
```

```http
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=password&client_id=my-app&username=user@example.com&password=secret
```

Each password-grant request then emits a `DeprecationWarning`. The warning does
not include the username, password, client or token. Python hides
`DeprecationWarning` outside `__main__` by default, so to find remaining callers
run with `-W default::DeprecationWarning`, or record them with an
`after("token.password")` [hook](/docs/hooks#tokenpassword). In the OpenAPI
schema only the password variant of the `/token` request is marked `deprecated`;
the endpoint and the authorization code grant are not deprecated.

To migrate:

- SPA and native clients: use the authorization code grant with PKCE above.
- First-party password sign-in: post the password to your own endpoint, check it
  with `auth.authenticate()`, then call `auth.login()` for a cookie session or
  `auth.issue_session_token()` for a bearer token. Django projects use Django's
  own login views. Your endpoint owns its CSRF protection and rate limits.

Password sign-in through your own endpoint is not deprecated. Only the OAuth
password grant at `/token` is.

Cross-Auth 1.0 removes the grant and `OAuthServer`'s `password_grant` option.

## Token Usage

Use the returned `access_token` as a bearer token:

```http
Authorization: Bearer <access_token>
```

Cross-Auth stores the token hash in `SessionStorage`, uses
`SessionConfig.max_age` for `expires_in`, and can revoke tokens with the
session-management APIs.

## Social Login

Cross-Auth supports social login via OAuth 2.0 providers. See the
[Social Providers](/docs/social-providers) guide for configuration details.

## Sharing provider connections

Cross-Auth defaults to exclusive ownership: a provider identity belongs to one
application user. Enable shared integration connections explicitly:

```python
config = {
    "account_linking": {
        "enabled": True,
        "allow_shared_connections": True,
    },
}
```

The flag controls application checks; your database constraints must match it.
Use global identity uniqueness for exclusive ownership, or per-user uniqueness
plus a unique login-owner index for sharing. Changing the flag does not migrate
the schema. Exclusive policy checks alone cannot prevent concurrent shared
attachments if the database still uses the shared schema.

This applies to every provider. It does not bypass the existing verified-email
or different-email policies. Set `account_linking.allow_different_emails`
separately when your application needs it.

For example, a GitHub account can supply repositories to both a work account and
a personal account while only identifying the personal account at sign-in:

| Application user | GitHub identity | API access | Login enabled |
| ---------------- | --------------- | ---------- | ------------- |
| Work             | `patrick91`     | Yes        | No            |
| Personal         | `patrick91`     | Yes        | Yes           |

The connect flow creates integration-only connections and reconnecting refreshes
credentials without changing login eligibility. The authenticated link flow can
also enable login: send `allow_login: true` to `finalize-link` to create a login
method or promote the current user's existing connection after provider
verification. If another user already owns login for that identity, Cross-Auth
rejects the promotion with `account_already_linked` before updating credentials.
Omitting `allow_login` or setting it to `false` preserves an existing
connection's login eligibility; it never disables login. Ordinary sign-in cannot
promote a connection.

Each user can have only one connection to a given provider identity, and that
identity can identify at most one user for login, under either schema. Sign-in
selects that login owner. If connections exist but none enable login, sign-in is
rejected: Cross-Auth does not pick a user, create another user, or enable login
automatically.

Credentials are stored per connection. Updating or disconnecting the work
connection does not update or delete the personal connection. Providers may
reuse grants or tokens across authorizations; provider-side revocation can still
affect other connections.

To return to exclusive ownership, first resolve identities connected to multiple
users, then add the global unique constraint. Choose which connections to retain
explicitly; a schema migration must not merge accounts or transfer login
ownership automatically. Use the
[storage migration guidance](/docs/storage#connection-ownership-and-migration)
before enabling sharing or upgrading a custom storage implementation.

## Browser binding and callback lifecycle

Each OAuth attempt sets its own random, HttpOnly, host-only cookie with
`SameSite=Lax`, path `/`, and a ten-minute lifetime. HTTPS uses `Secure` and the
`__Host-` cookie prefix. HTTP cookies are intended for local development. Behind
a proxy, configure `base_url` with the public HTTPS URL so cookie security and
callback URLs use the same origin.

The callback must present that cookie and match the stored provider. The cookie
is independent of the login session and cannot be replaced by the `state` URL
parameter. Multiple tabs can have separate pending attempts. A completed
callback consumes its state atomically and deletes its cookie. Abandoned cookies
and stored requests expire after ten minutes.

Missing or incorrect browser cookies and wrong-provider callbacks do not consume
the request, so someone holding only its URL cannot cancel the legitimate
attempt. After those checks succeed, the state is consumed even if the provider
reports an error or its token exchange fails; start a new attempt to retry.

Connect requires the initiating user to remain signed in at callback. Link also
rejects a different signed-in user at callback, but allows a callback without a
login session because bearer clients cannot forward their Authorization header
through the provider's redirect. Finalize-link always requires the initiating
user, the matching provider, and the PKCE verifier. A valid finalization
consumes its link code before exchanging provider tokens; failures require
restarting the link flow. Incorrect users, providers, or verifiers do not
consume that code.

For Apple and other form-post callbacks, Cross-Auth temporarily stores the POST
payload and returns a 303 redirect to a one-time continuation URL.
Authentication runs on the subsequent GET, where the browser sends its
`SameSite=Lax` cookies. Provider codes and profile data are kept out of the
continuation URL. This does not require changing the session cookie to
`SameSite=None`.

Cross-origin browser calls to `POST /{provider}/link` must use
`credentials: "include"` so the response can set the binding cookie. Configure
CORS with an explicit allowed origin and credentials enabled. Cookie
restrictions still apply for deployments on different sites; prefer hosting the
auth endpoint on the application's site.

### Upgrading from unbound OAuth state

Existing login sessions and issued tokens are unaffected. Pending authorization
requests and link codes from previous versions must be restarted. New workers
use versioned storage keys and reject records without binding metadata; old
workers cannot complete new attempts.

Deploy initiation, callback, and finalize-link endpoints together, or route an
entire flow to the updated worker pool during a rolling deployment.
Mixed-version routing can force users to restart login, and old workers retain
their previous behavior until drained. Do not fall back to accepting an unbound
state record.
