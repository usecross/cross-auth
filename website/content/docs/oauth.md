---
title: OAuth 2.0
description: OAuth 2.0 authorization code flow with PKCE support.
order: 3
section: Guides
---

## Overview

Cross-Auth implements the OAuth 2.0 authorization code flow with PKCE (Proof Key for Code Exchange). This is used when Cross-Auth acts as the authorization server -- for example, when your SPA or mobile app needs to obtain tokens.

## Supported Grant Types

### Authorization Code Grant (with PKCE)

The recommended flow for public clients (SPAs, mobile apps):

1. Client generates a `code_verifier` and derives a `code_challenge` (S256).
2. Client redirects the user to the authorization endpoint with the `code_challenge`.
3. User authenticates and authorizes the request.
4. Server returns an authorization code to the client's redirect URI.
5. Client exchanges the code + `code_verifier` for an access token at the token endpoint.

### Password Grant

Available for first-party applications where the client is trusted:

```
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=password&client_id=my-app&username=user@example.com&password=secret
```

> **Note:** The password grant is less secure than the authorization code flow and should only be used by first-party clients.

## Social Login

Cross-Auth supports social login via OAuth 2.0 providers. See the [Social Providers](/docs/social-providers) guide for configuration details.
