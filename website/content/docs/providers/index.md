---
title: OAuth Providers
description: Configure OAuth providers for authentication
section: Providers
order: 1
---

# OAuth Providers

Cross Auth supports multiple OAuth providers with built-in PKCE support,
including OIDC providers and standard OAuth2 providers.

## Available Providers

| Provider                           | Type   | PKCE | Notes                            |
| ---------------------------------- | ------ | ---- | -------------------------------- |
| [Apple](/docs/providers/apple)     | OIDC   | Yes  | JWT client secret, POST callback |
| [Google](/docs/providers/google)   | OIDC   | Yes  | ID token validation with JWKS    |
| [GitHub](/docs/providers/github)   | OAuth2 | Yes  | Userinfo endpoint                |
| [Discord](/docs/providers/discord) | OAuth2 | Yes  | Userinfo endpoint                |

## OIDC vs OAuth2

**OIDC providers** (Apple, Google, Microsoft) return an `id_token` JWT
containing user claims. Cross Auth validates this token locally using the
provider's public keys (JWKS) - no extra HTTP request needed.

**OAuth2 providers** (GitHub, Discord) require a separate call to a userinfo
endpoint to fetch user data after token exchange.

## Application setup

Configure each provider using its page, then pass the instances together in your
`providers` list. Use the shared
[session sign-in or OAuth client setup](/docs/oauth#the-oauth-server) for the
application wiring: cookie sign-in uses `/{provider}/login`; client token flows
use `/{provider}/authorize` with an `OAuthServer`, registered clients, and PKCE.
The provider credentials and your application's OAuth client registrations are
separate.

## Custom Providers

See [Custom Providers](/docs/providers/custom) for creating your own OAuth2 or
OIDC provider.
