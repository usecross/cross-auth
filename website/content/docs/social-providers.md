---
title: Social Providers
description: Add social login with GitHub, Google, and other OAuth providers.
order: 4
section: Guides
---

## Overview

Cross-Auth supports social login through OAuth 2.0 providers. Users can sign in
with their existing accounts from services like GitHub and Google, and
Cross-Auth will create or link accounts in your storage.

## How It Works

1. The user clicks "Sign in with GitHub" (or another provider).
2. Your app redirects to the provider's authorization URL.
3. The user authorizes your app.
4. The provider redirects back to your app with an authorization code.
5. Cross-Auth exchanges the code for user info and creates/links the account.

## Account Linking

Cross-Auth supports linking multiple social accounts to a single user. If a user
signs in with GitHub and later connects their Google account, both providers are
linked to the same user record via the `SocialAccount` model.

The `POST /{provider}/link` endpoint handles account linking for authenticated
users.

The `DELETE /{provider}/social-accounts` endpoint disconnects the current user's
provider account when only one account for that provider is connected. If a user
has multiple accounts for the same provider, use
`DELETE /{provider}/social-accounts/{social_account_id}` to choose the account
explicitly. Cross-Auth verifies the selected social account belongs to the
current user and provider, and blocks disconnecting it when it is the user's
only login method. The check and deletion are atomic, so two simultaneous
disconnects cannot remove the last two login methods. Use the `oauth.disconnect`
hooks to add provider-specific cleanup such as cache invalidation, token
revocation, or audit events.

## Configuration

Each provider requires:

- **Client ID** -- From the provider's developer console.
- **Client Secret** -- From the provider's developer console.
- **Redirect URI** -- The callback URL in your app.

## Native Sign-In (id_token)

Native apps don't redirect: Apple's ASAuthorization and Google's Credential
Manager hand the app a signed **id_token** directly, and the app posts it to
your API — a GraphQL sign-in mutation, a REST endpoint. Validate it and sign the
user in with `sign_in_with_id_token`:

```python
user, created = auth.sign_in_with_id_token(
    "apple",
    identity_token,
    # Apple sends the name only on first authorization, outside the token.
    user_info={"first_name": first_name, "last_name": last_name},
    nonce=raw_nonce,  # optional; matched raw or SHA-256 against the claim
)
token, record = auth.issue_session_token(str(user.id), metadata={"client_name": "ios"})
```

The token is validated against the provider's JWKS (signature, issuer, audience,
expiry, issued-at time, and subject), then the user is found or created by the
same core the web callback uses: normalized email lookup, the account-linking
policy gate, and your `user.create`, `social_account.create`, and
`social_account.update` hooks. No OAuth token exchange happens, so no access or
refresh tokens are stored on the social account. The `oauth.id_token` hooks also
run around the outer flow.

Only OIDC providers issue id_tokens, so this works for Apple and Google (and any
`OIDCProvider` subclass); providers without an id_token, like GitHub, raise
`invalid_request`. To let a native sign-in attach to an existing account with
the same email, enable account linking (see above) — otherwise a matching email
raises `account_not_linked`.

### Nonce handling

When the native SDK supports a nonce, generate a fresh unpredictable value for
each sign-in and pass the expected raw value as `nonce=`. Cross-Auth accepts an
exact match or its SHA-256 hexadecimal digest, for SDK integrations that hash
the value before sending it to the provider. Empty values and missing or
mismatched token nonce claims are rejected when `nonce=` is supplied.

The application owns challenge storage, binding to the initiating client, and
single-use consumption. Accepting both the token and its expected nonce from an
untrusted request does not by itself prevent replay. Without `nonce=`,
Cross-Auth validates the token but does not check a nonce or make the token
single-use.

Browser OIDC flows manage the nonce automatically. Cross-Auth generates a fresh
value for each session login, token login, account connection, or account link.
It saves the value with the authorization request and sends it to the provider.
The signed ID token must contain that exact nonce before user or account storage
is changed. Linking retains the nonce until the token exchange at finalize-link.
Apple form-post callbacks retain it through the existing GET continuation.

`nonce` is a library-controlled parameter, like `state`. A nonce in OIDC
`extra_authorization_params` is ignored, so it cannot replace the per-attempt
value. Browser nonces use exact matching; the raw-or-SHA-256 compatibility above
applies only to native sign-in.

Pending browser authorizations or link codes created before this upgrade have no
stored nonce and must be restarted. Custom `build_authorization_url`,
`build_authorization_params`, and `fetch_user_info` overrides must accept and
forward the optional `provider_data` keyword. Core passes the stored dictionary
returned by `get_authorization_data()`: a fresh nonce for OIDC and an empty
dictionary for ordinary OAuth providers by default.
