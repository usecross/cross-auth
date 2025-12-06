---
title: Apple Sign In
description: Configure Apple Sign In for authentication
section: Providers
order: 2
---

# Apple Sign In

Apple Sign In uses OpenID Connect (OIDC) with some unique requirements compared to other providers.

## Configuration

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

## Apple Developer Setup

1. Go to [Apple Developer Portal](https://developer.apple.com/account)
2. Navigate to **Certificates, Identifiers & Profiles**

### Create an App ID

1. Go to **Identifiers** → **App IDs**
2. Click **+** to create a new App ID
3. Enable **Sign in with Apple** capability
4. Save the App ID

### Create a Service ID

1. Go to **Identifiers** → **Service IDs**
2. Click **+** to create a new Service ID
3. Enter a description and identifier (e.g., `com.your-app.service`)
4. Enable **Sign in with Apple**
5. Click **Configure**:
   - Add your domain (e.g., `your-app.com`)
   - Add redirect URL: `https://your-app.com/auth/apple/callback`
6. Save - the identifier is your `client_id`

### Create a Key

1. Go to **Keys**
2. Click **+** to create a new Key
3. Enable **Sign in with Apple**
4. Click **Configure** and select your App ID
5. Register the key
6. **Download the `.p8` file** (you can only download once!)
7. Note the **Key ID** - this is your `key_id`

### Find Your Team ID

Your Team ID is in the top-right of the Apple Developer Portal, or in **Membership Details**. It's a 10-character alphanumeric string.

## Important Notes

### POST Callback

Apple uses `response_mode=form_post`, so the OAuth callback comes via POST request instead of GET. Cross Auth handles this automatically.

### First-Time Data Only

Apple sends the user's name and email **only on the first authorization**. On subsequent logins, you only get the user ID. Store user data immediately when you first receive it.

```python
# In your callback handler, check for first_name/last_name
user_info = ...  # from Cross Auth
if user_info.get("first_name"):
    # First authorization - save the name!
    save_user_name(user_info["first_name"], user_info["last_name"])
```

### Private Relay Email

Users can choose to hide their real email address. Apple provides a private relay address like `abc123@privaterelay.appleid.com`. Check the `is_private_email` field:

```python
if user_info.get("is_private_email"):
    # User is using Apple's private relay
    # Emails sent to this address will be forwarded
    pass
```

### JWT Client Secret

Unlike other OAuth providers that use a static client secret, Apple requires a JWT signed with your private key. Cross Auth generates this automatically on each token exchange.

## User Info

Apple returns the following user information:

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Stable user identifier (from `sub` claim) |
| `email` | string | User's email (may be private relay) |
| `email_verified` | boolean | Whether email is verified |
| `is_private_email` | boolean | Whether using Apple's private relay |
| `first_name` | string | User's first name (first auth only) |
| `last_name` | string | User's last name (first auth only) |

## Troubleshooting

### "invalid_client" Error

- Verify your Service ID is correctly configured with Sign in with Apple
- Check that the redirect URL matches exactly
- Ensure your private key hasn't expired

### No Email Received

- User may have chosen not to share their email
- On subsequent logins, email may not be included - use the stored value

### Callback Returns 405 Method Not Allowed

Your web framework isn't accepting POST requests on the callback URL. Cross Auth's `AuthRouter` handles this automatically, but if using a custom setup, ensure POST is allowed.
