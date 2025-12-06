---
title: Custom Providers
description: Create custom OAuth2 and OIDC providers
section: Providers
order: 5
---

# Custom Providers

Cross Auth provides two base classes for creating custom providers:

- **OAuth2Provider** - For providers using a userinfo endpoint
- **OIDCProvider** - For providers returning an `id_token` JWT

## OAuth2 Provider

Use `OAuth2Provider` for providers like GitHub, Discord, or any service that requires fetching user info from a separate endpoint.

```python
from cross_auth.social_providers.oauth import OAuth2Provider, UserInfo

class CustomProvider(OAuth2Provider):
    id = "custom"

    # Required endpoints
    authorization_endpoint = "https://provider.com/oauth/authorize"
    token_endpoint = "https://provider.com/oauth/token"
    user_info_endpoint = "https://provider.com/api/user"

    # OAuth settings
    scopes = ["profile", "email"]
    supports_pkce = True

    def __init__(self, client_id: str, client_secret: str):
        super().__init__(client_id=client_id, client_secret=client_secret)

    def fetch_user_info(self, access_token: str) -> UserInfo:
        """Fetch and normalize user info from the provider."""
        import httpx

        response = httpx.get(
            self.user_info_endpoint,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        response.raise_for_status()
        data = response.json()

        return {
            "id": str(data["user_id"]),
            "email": data.get("email"),
            # Add any other fields your app needs
        }
```

### Required Class Attributes

| Attribute | Description |
|-----------|-------------|
| `id` | Unique identifier for the provider (used in URLs) |
| `authorization_endpoint` | URL to redirect users for authorization |
| `token_endpoint` | URL to exchange code for tokens |
| `user_info_endpoint` | URL to fetch user profile |
| `scopes` | List of OAuth scopes to request |

### Optional Attributes

| Attribute | Default | Description |
|-----------|---------|-------------|
| `supports_pkce` | `False` | Enable PKCE for enhanced security |

## OIDC Provider

Use `OIDCProvider` for providers that return an `id_token` JWT containing user claims. This is more efficient as it doesn't require an extra HTTP request.

```python
from cross_auth.social_providers.oidc import OIDCProvider
from cross_auth.social_providers.oauth import UserInfo
from typing import Any

class GoogleProvider(OIDCProvider):
    id = "google"

    # OAuth endpoints
    authorization_endpoint = "https://accounts.google.com/o/oauth2/v2/auth"
    token_endpoint = "https://oauth2.googleapis.com/token"

    # OIDC configuration
    jwks_uri = "https://www.googleapis.com/oauth2/v3/certs"
    issuer = "https://accounts.google.com"
    jwks_cache_key = "google:jwks"

    scopes = ["openid", "email", "profile"]
    supports_pkce = True

    def __init__(self, client_id: str, client_secret: str):
        super().__init__(client_id=client_id, client_secret=client_secret)

    def extract_user_info_from_claims(
        self,
        claims: dict[str, Any],
        extra: dict[str, Any] | None = None,
    ) -> UserInfo:
        """Extract user info from id_token claims."""
        return {
            "id": claims["sub"],
            "email": claims.get("email"),
            "name": claims.get("name"),
            "picture": claims.get("picture"),
        }
```

### Required OIDC Attributes

| Attribute | Description |
|-----------|-------------|
| `jwks_uri` | URL to fetch provider's public keys (JWKS) |
| `issuer` | Expected `iss` claim value for validation |
| `jwks_cache_key` | Key for caching JWKS in secondary storage |

### How OIDC Validation Works

1. Provider returns `id_token` JWT in token response
2. Cross Auth fetches the provider's public keys from `jwks_uri`
3. JWT signature is verified against the public keys
4. Claims are validated: `iss`, `aud`, `exp`
5. User info is extracted from the validated claims

Keys are cached in secondary storage and automatically refreshed on rotation.

## Customizing Behavior

### Custom Authorization Parameters

Override `build_authorization_params` to add provider-specific parameters:

```python
def build_authorization_params(
    self,
    state: str,
    proxy_redirect_uri: str,
    response_type: str,
    code_challenge: str | None = None,
    code_challenge_method: str | None = None,
    login_hint: str | None = None,
) -> dict:
    params = super().build_authorization_params(
        state, proxy_redirect_uri, response_type,
        code_challenge, code_challenge_method, login_hint,
    )
    # Add custom parameters
    params["prompt"] = "consent"
    params["access_type"] = "offline"
    return params
```

### Custom Token Exchange

Override `build_token_exchange_params` for providers with non-standard token exchange:

```python
def build_token_exchange_params(
    self, code: str, redirect_uri: str, code_verifier: str | None = None
) -> TokenExchangeParams:
    params = super().build_token_exchange_params(code, redirect_uri, code_verifier)
    # Modify as needed
    return params
```

### Custom Callback Handling

Override `extract_callback_data` for providers that send callback data differently (e.g., POST instead of GET):

```python
from cross_auth.social_providers.oauth import CallbackData

async def extract_callback_data(self, request: AsyncHTTPRequest) -> CallbackData:
    # Example: Extract from POST form data
    form_data = await request.get_form_data()
    return CallbackData(
        code=form_data.form.get("code"),
        state=form_data.form.get("state"),
        error=form_data.form.get("error"),
        extra={"custom_field": form_data.form.get("custom")},
    )
```

## Finding Provider Documentation

Most providers document their OAuth/OIDC implementation:

| Provider | Documentation |
|----------|---------------|
| Google | [OAuth 2.0 for Web Server Applications](https://developers.google.com/identity/protocols/oauth2/web-server) |
| Microsoft | [Microsoft Identity Platform](https://learn.microsoft.com/en-us/azure/active-directory/develop/) |
| Okta | [OAuth 2.0 and OIDC](https://developer.okta.com/docs/concepts/oauth-openid/) |
| Auth0 | [Authentication API](https://auth0.com/docs/api/authentication) |

Look for:
- Authorization endpoint URL
- Token endpoint URL
- Userinfo endpoint (OAuth2) or JWKS URI (OIDC)
- Available scopes
- User info response format
