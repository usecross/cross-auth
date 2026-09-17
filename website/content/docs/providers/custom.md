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

Use `OAuth2Provider` for providers like GitHub, Discord, or any service that
requires fetching user info from a separate endpoint.

```python
from typing import Any

from cross_auth import Context, OAuth2Provider, TokenResponse, UserInfo


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

    def fetch_user_info(
        self,
        token_response: TokenResponse,
        context: Context,
        extra: dict[str, Any] | None = None,
    ) -> UserInfo:
        """Fetch and normalize user info from the provider."""
        import httpx

        response = httpx.get(
            self.user_info_endpoint,
            headers={"Authorization": f"Bearer {token_response.access_token}"},
        )
        response.raise_for_status()
        data = response.json()

        return {
            "id": str(data["user_id"]),
            "email": data.get("email"),
            "email_verified": data.get("email_verified"),
            # Add any other fields your app needs
        }
```

### Required Class Attributes

| Attribute                | Description                                       |
| ------------------------ | ------------------------------------------------- |
| `id`                     | Unique identifier for the provider (used in URLs) |
| `authorization_endpoint` | URL to redirect users for authorization           |
| `token_endpoint`         | URL to exchange code for tokens                   |
| `user_info_endpoint`     | URL to fetch user profile                         |
| `scopes`                 | List of OAuth scopes to request                   |

### Optional Attributes

| Attribute       | Default | Description                       |
| --------------- | ------- | --------------------------------- |
| `supports_pkce` | `False` | Enable PKCE for enhanced security |

## OIDC Provider

Use `OIDCProvider` for providers that return an `id_token` JWT containing user
claims. This is more efficient as it doesn't require an extra HTTP request.

```python
from typing import Any

from cross_auth import OIDCProvider, UserInfo


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
            "email_verified": claims.get("email_verified"),
            "name": claims.get("name"),
        }
```

### Required OIDC Attributes

| Attribute        | Description                                |
| ---------------- | ------------------------------------------ |
| `jwks_uri`       | URL to fetch provider's public keys (JWKS) |
| `issuer`         | Expected `iss` claim value for validation  |
| `jwks_cache_key` | Key for caching JWKS in secondary storage  |

### How OIDC Validation Works

1. Provider returns `id_token` JWT in token response
2. Cross Auth fetches the provider's public keys from `jwks_uri`
3. JWT signature is verified against the public keys
4. Required claims are validated: `iss`, `sub`, `aud`, `exp`, and `iat`
5. User info is extracted from the validated claims

Keys are cached in secondary storage and automatically refreshed on rotation.

Cross-Auth requires the standard
[OIDC ID token claims](https://openid.net/specs/openid-connect-core-1_0.html#IDToken).
The subject must be a nonempty string. Expiry and issued-at values must be
finite JSON numbers, rather than numeric strings or booleans. An optional `nbf`
must also be a valid numeric date. Existing issuer, audience, signature, expiry,
and future-issued-token checks apply to both browser and native sign-in.

The configured `client_id` must be in the audience. Cross-Auth does not
currently apply a separate `azp` presenter allowlist: Google documents valid
[hybrid web and mobile applications](https://developers.google.com/identity/openid-connect/openid-connect)
whose authorized presenter differs from the audience. Applications needing a
presenter restriction must enforce their own allowed client IDs in provider
validation.

## Customizing Behavior

### Stored Authorization Data

`get_authorization_data()` returns a fresh `dict[str, str]` for each attempt.
The base OAuth provider returns an empty dictionary; OIDC generates a nonce.
Cross-Auth stores the result as `provider_data` on the authorization request and
carries it through link redemption.

`build_authorization_url`, `build_authorization_params`, and `fetch_user_info`
receive it through the optional `provider_data` keyword. The provider chooses
which values to include in the authorization URL; stored values are not
forwarded automatically. OIDC subclasses extending the getter should include
`super().get_authorization_data()` to retain nonce generation.

Providers can validate stored data at two stages:

- `validate_auth_request(auth_request)` receives the complete `AuthRequest`
  before processing the browser callback.
- `validate_link_data(link_data)` receives the complete `LinkCodeData` when the
  app redeems a link code, before exchanging the provider code.

Each method can inspect the nonce, expiry, client, user, and other fields on its
record. The base OAuth provider performs no additional checks; OIDC requires a
stored nonce at both stages. Override either method to customize provider
requirements, raising `OAuth2Exception` on failure. OIDC subclasses should call
`super()` to preserve the nonce requirement.

### Custom Authorization Parameters

Override `build_authorization_params` to add provider-specific parameters:

```python
from cross_web import HTTPRequest


def build_authorization_params(
    self,
    state: str,
    redirect_uri: str,
    *,
    request: HTTPRequest | None = None,
    code_challenge: str | None = None,
    code_challenge_method: str | None = None,
    login_hint: str | None = None,
    provider_data: dict[str, str] | None = None,
) -> dict[str, str]:
    params = super().build_authorization_params(
        state=state,
        redirect_uri=redirect_uri,
        request=request,
        provider_data=provider_data,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        login_hint=login_hint,
    )
    # Add custom parameters
    params["prompt"] = "consent"
    params["access_type"] = "offline"
    return params
```

### Custom Token Exchange

Override `build_token_exchange_params` for providers with non-standard token
exchange:

```python
from cross_auth import TokenExchangeParams


def build_token_exchange_params(
    self, code: str, redirect_uri: str, code_verifier: str | None = None
) -> TokenExchangeParams:
    params = super().build_token_exchange_params(code, redirect_uri, code_verifier)
    # Modify as needed
    return params
```

### Custom Token Response Parsing

Override `parse_token_response` when a provider returns a non-standard response
body. Return either `TokenResponse` or `TokenErrorResponse` directly:

```python
import httpx

from cross_auth import TokenResponse
from cross_auth.models.oauth_token_response import TokenErrorResponse


def parse_token_response(
    self, response: httpx.Response
) -> TokenResponse | TokenErrorResponse:
    data = response.json()

    if error := data.get("provider_error"):
        return TokenErrorResponse(
            error=error,
            error_description=data.get("provider_error_description"),
        )

    return TokenResponse.model_validate(data["tokens"])
```

Custom parsers written for Cross Auth 0.22 or earlier may return an
`OAuth2TokenEndpointResponse` wrapper. That wrapper has been removed. Update the
override to return its `TokenResponse` or `TokenErrorResponse` value directly;
the models and their wire formats are unchanged.

### Custom Callback Handling

Override `extract_callback_params` for providers that send callback data
differently (e.g., POST instead of GET):

```python
from cross_auth import CallbackData
from cross_web import AsyncHTTPRequest


async def extract_callback_params(self, request: AsyncHTTPRequest) -> CallbackData:
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

| Provider  | Documentation                                                                                               |
| --------- | ----------------------------------------------------------------------------------------------------------- |
| Google    | [OAuth 2.0 for Web Server Applications](https://developers.google.com/identity/protocols/oauth2/web-server) |
| Microsoft | [Microsoft Identity Platform](https://learn.microsoft.com/en-us/azure/active-directory/develop/)            |
| Okta      | [OAuth 2.0 and OIDC](https://developer.okta.com/docs/concepts/oauth-openid/)                                |
| Auth0     | [Authentication API](https://auth0.com/docs/api/authentication)                                             |

Look for:

- Authorization endpoint URL
- Token endpoint URL
- Userinfo endpoint (OAuth2) or JWKS URI (OIDC)
- Available scopes
- User info response format
