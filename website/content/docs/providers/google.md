---
title: Google
description: Configure Google OAuth for authentication
section: Providers
order: 3
---

# Google

Google uses OAuth 2.0 with OpenID Connect. Cross Auth validates Google's
`id_token` locally using Google's JWKS endpoint.

## Configuration

```python
from cross_auth.social_providers.google import GoogleProvider

google = GoogleProvider(
    client_id="your-google-client-id",
    client_secret="your-google-client-secret",
)
```

### Account linking and `trust_email`

Unlike other providers, `GoogleProvider` defaults `trust_email=False`. Google
always returns an `email_verified` claim in the ID token, so auto-linking uses
that claim instead of blanket-trusting the email. If account linking is enabled
and a user's `email_verified` is `False` (rare, but possible for federated
Google accounts), linking will be skipped. Pass `trust_email=True` explicitly
only if you want to override this.

### Requesting a refresh token

Google only issues a `refresh_token` when the authorization request includes
`access_type=offline`, and only re-issues one on subsequent sign-ins if you also
pass `prompt=consent`:

```python
google = GoogleProvider(
    client_id="your-google-client-id",
    client_secret="your-google-client-secret",
    extra_authorization_params={
        "access_type": "offline",
        "prompt": "consent",
    },
)
```

### Restricting to a Google Workspace domain

`extra_authorization_params` can also pass `hd` (Workspace domain hint) and
`include_granted_scopes` (incremental authorization):

```python
google = GoogleProvider(
    client_id="...",
    client_secret="...",
    extra_authorization_params={"hd": "example.com"},
)
```

> The `hd` request parameter is a UX hint only — it is not a security boundary.
> To actually restrict sign-in to a Workspace domain, subclass `GoogleProvider`
> and validate the `hd` claim from the verified ID token in
> `extract_user_info_from_claims`.

## Google Setup

### Create an OAuth Client

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Select your project
3. Navigate to **APIs & Services** → **Credentials**
4. Click **Create Credentials** → **OAuth client ID**
5. Select **Web application**
6. Add your authorized redirect URI:
   - `https://your-app.com/auth/google/callback`
7. Copy the **Client ID** and **Client secret**

## Scopes

The Google provider requests these scopes by default:

| Scope     | Description               |
| --------- | ------------------------- |
| `openid`  | Enables OpenID Connect    |
| `email`   | Access user's email       |
| `profile` | Access basic profile data |

## User Info

Google returns the following user information in the ID token:

| Field            | Type    | Description               |
| ---------------- | ------- | ------------------------- |
| `sub`            | string  | Stable Google user ID     |
| `email`          | string  | User's email address      |
| `email_verified` | boolean | Whether email is verified |
| `name`           | string  | Display name              |
| `picture`        | string  | Profile picture URL       |

Cross Auth maps `sub` to the standard user info `id` field.

## Example

```python
from fastapi import FastAPI
from cross_auth.router import AuthRouter
from cross_auth.social_providers.google import GoogleProvider

google = GoogleProvider(
    client_id="123.apps.googleusercontent.com",
    client_secret="secret123",
)

auth_router = AuthRouter(
    providers=[google],
    # ... other config
)

app = FastAPI()
app.include_router(auth_router, prefix="/auth")
```

Users can then authenticate via:

- `GET /auth/google/authorize` - Start OAuth flow
- `GET /auth/google/callback` - OAuth callback (handled automatically)

## Testing With a Mock Provider

For local or CI tests, you can override endpoints:

```python
google = GoogleProvider(
    client_id="test-google-client-id",
    client_secret="test-google-client-secret",
    authorization_endpoint="https://google-oauth-mock.example.com/o/oauth2/v2/auth",
    token_endpoint="https://google-oauth-mock.example.com/token",
    jwks_uri="https://google-oauth-mock.example.com/oauth2/v3/certs",
)
```

## Troubleshooting

### "id_token audience mismatch"

- Ensure the `client_id` matches the OAuth client configured in Google Cloud

### "id_token issuer mismatch"

- The token's `iss` claim must be either `https://accounts.google.com` or
  `accounts.google.com` — both forms are valid per Google's docs

### "Key not found in provider's JWKS"

- Ensure `jwks_uri` points to a JWKS endpoint that contains the key ID from the
  token header
