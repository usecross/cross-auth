---
title: OAuth Providers
description: Configure OAuth providers for authentication
section: Core Concepts
order: 1
---

# OAuth Providers

Cross Auth supports multiple OAuth providers with built-in PKCE support, including OIDC providers (Apple, Google) and standard OAuth2 providers (GitHub, Discord).

## Apple Sign In

Apple Sign In uses OpenID Connect (OIDC) with some unique requirements:

```python
from cross_auth.social_providers.apple import AppleProvider, AppleAuthConfig

apple = AppleProvider(
    config=AppleAuthConfig(
        client_id="com.your-app.service",  # Your Service ID
        team_id="XXXXXXXXXX",               # 10-character Team ID
        key_id="XXXXXXXXXX",                # Key ID for your private key
        private_key="""-----BEGIN PRIVATE KEY-----
...your ES256 private key...
-----END PRIVATE KEY-----""",
    )
)
```

### Apple Developer Setup

1. Go to [Apple Developer Portal](https://developer.apple.com/account)
2. Create an **App ID** with "Sign in with Apple" capability
3. Create a **Service ID** (this is your `client_id`)
   - Enable "Sign in with Apple"
   - Configure domains and redirect URLs
4. Create a **Key** with "Sign in with Apple" capability
   - Download the `.p8` file (this is your `private_key`)
   - Note the Key ID

### Important Notes

- **POST Callback**: Apple uses `response_mode=form_post`, so callbacks come via POST (Cross Auth handles this automatically)
- **First-time data only**: Apple sends user's name and email only on the first authorization. Store them immediately.
- **Private relay email**: Users can hide their real email. Check `is_private_email` in the user info.
- **JWT Client Secret**: Unlike other providers, the client secret is a JWT signed with your private key (generated automatically)

### User Info

Apple returns:
- `id` - Stable user identifier (sub claim)
- `email` - User's email (may be private relay)
- `email_verified` - Whether email is verified
- `is_private_email` - Whether using Apple's private relay
- `first_name`, `last_name` - Only on first authorization

## GitHub Provider

The GitHub provider fetches user email and profile information:

```python
from cross_auth.social_providers.github import GitHubProvider

github = GitHubProvider(
    client_id="your-github-client-id",
    client_secret="your-github-client-secret",
)
```

### GitHub OAuth App Setup

1. Go to GitHub Settings → Developer settings → OAuth Apps
2. Create a new OAuth App
3. Set Authorization callback URL to: `https://your-app.com/auth/github/callback`
4. Copy the Client ID and Client Secret

### Scopes

The GitHub provider requests the `user:email` scope to access verified email addresses.

## Discord Provider

The Discord provider fetches user profile and email:

```python
from cross_auth.social_providers.discord import DiscordProvider

discord = DiscordProvider(
    client_id="your-discord-client-id",
    client_secret="your-discord-client-secret",
)
```

### Discord Application Setup

1. Go to Discord Developer Portal
2. Create a new Application
3. Navigate to OAuth2 settings
4. Add redirect URL: `https://your-app.com/auth/discord/callback`
5. Copy the Client ID and Client Secret

### Scopes

The Discord provider requests `identify` and `email` scopes.

## Multiple Providers

You can use multiple providers simultaneously:

```python
auth_router = AuthRouter(
    providers=[github, discord],
    # ... other config
)
```

## Custom Providers

### Standard OAuth2 Provider

For providers that use a userinfo endpoint (like GitHub, Discord):

```python
from cross_auth.social_providers.oauth import OAuth2Provider

class CustomProvider(OAuth2Provider):
    id = "custom"
    authorization_endpoint = "https://provider.com/oauth/authorize"
    token_endpoint = "https://provider.com/oauth/token"
    user_info_endpoint = "https://provider.com/api/user"
    scopes = ["profile", "email"]
    supports_pkce = True
```

### OIDC Provider

For providers that return an `id_token` JWT (like Google, Microsoft, Okta):

```python
from cross_auth.social_providers.oidc import OIDCProvider

class GoogleProvider(OIDCProvider):
    id = "google"
    authorization_endpoint = "https://accounts.google.com/o/oauth2/v2/auth"
    token_endpoint = "https://oauth2.googleapis.com/token"

    # OIDC-specific configuration
    jwks_uri = "https://www.googleapis.com/oauth2/v3/certs"
    issuer = "https://accounts.google.com"
    jwks_cache_key = "google:jwks"

    scopes = ["openid", "email", "profile"]
    supports_pkce = True
```

OIDC providers validate the `id_token` JWT locally using the provider's public keys (JWKS), which is faster and more secure than calling a userinfo endpoint.
