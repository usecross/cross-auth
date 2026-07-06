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
only login method. Use the `oauth.disconnect` hooks to add provider-specific
cleanup such as cache invalidation, token revocation, or audit events.

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
expiry), then the user is found or created by the same core the web callback
uses: normalized email lookup, the account-linking policy gate, and your
accounts-storage signup hooks. No OAuth token exchange happens, so no access or
refresh tokens are stored on the social account. The `oauth.id_token` hooks run
around the flow.

Only OIDC providers issue id_tokens, so this works for Apple and Google (and any
`OIDCProvider` subclass); providers without an id_token, like GitHub, raise
`invalid_request`. To let a native sign-in attach to an existing account with
the same email, enable account linking (see above) — otherwise a matching email
raises `account_not_linked`.
