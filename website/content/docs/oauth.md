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
`CrossAuth` to enable token issuance; without it, `/token` returns an OAuth
error instead of minting a token.

### Password Grant

Available for first-party applications where the client is trusted:

```http
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=password&client_id=my-app&username=user@example.com&password=secret
```

> **Note:** The password grant is less secure than the authorization code flow
> and should only be used by first-party clients.

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

The connect flow creates integration-only connections. The link flow uses its
`allow_login` setting for new connections. Reconnecting an existing connection
refreshes its credentials without changing its login eligibility. There is no
implicit promotion of a connection to a login method.

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
