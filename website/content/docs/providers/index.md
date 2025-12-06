---
title: OAuth Providers
description: Configure OAuth providers for authentication
section: Providers
order: 1
---

# OAuth Providers

Cross Auth supports multiple OAuth providers with built-in PKCE support, including OIDC providers and standard OAuth2 providers.

## Available Providers

| Provider | Type | PKCE | Notes |
|----------|------|------|-------|
| [Apple](/docs/providers/apple) | OIDC | Yes | JWT client secret, POST callback |
| [GitHub](/docs/providers/github) | OAuth2 | Yes | Userinfo endpoint |
| [Discord](/docs/providers/discord) | OAuth2 | Yes | Userinfo endpoint |

## OIDC vs OAuth2

**OIDC providers** (Apple, Google, Microsoft) return an `id_token` JWT containing user claims. Cross Auth validates this token locally using the provider's public keys (JWKS) - no extra HTTP request needed.

**OAuth2 providers** (GitHub, Discord) require a separate call to a userinfo endpoint to fetch user data after token exchange.

## Multiple Providers

You can use multiple providers simultaneously:

```python
from cross_auth.router import AuthRouter
from cross_auth.social_providers.apple import AppleProvider, AppleAuthConfig
from cross_auth.social_providers.github import GitHubProvider

auth_router = AuthRouter(
    providers=[apple, github, discord],
    # ... other config
)
```

## Custom Providers

See [Custom Providers](/docs/providers/custom) for creating your own OAuth2 or OIDC provider.
