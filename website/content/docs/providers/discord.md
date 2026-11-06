---
title: Discord
description: Configure Discord OAuth for authentication
section: Providers
order: 5
---

# Discord

Discord uses standard OAuth 2.0 with a userinfo endpoint to fetch user data.

## Configuration

```python
from cross_auth.social_providers.discord import DiscordProvider

discord = DiscordProvider(
    client_id="your-discord-client-id",
    client_secret="your-discord-client-secret",
)
```

Discord reports whether the user's email is verified. Linking a Discord sign-in
to an existing user by email requires a verified email; see
[Linking by email](/docs/social-providers#linking-by-email).

## Discord Setup

### Create an Application

1. Go to [Discord Developer Portal](https://discord.com/developers/applications)
2. Click **New Application**
3. Enter a name and create the application
4. Navigate to **OAuth2** in the sidebar

### Configure OAuth2

1. In **OAuth2** → **General**:

   - Copy the **Client ID**
   - Click **Reset Secret** and copy the **Client Secret**

2. In **OAuth2** → **Redirects**:
   - Click **Add Redirect**
   - Enter: `https://your-app.com/auth/discord/callback`
   - Save changes

## Scopes

The Discord provider requests these scopes by default:

| Scope      | Description                        |
| ---------- | ---------------------------------- |
| `identify` | Access user's ID, username, avatar |
| `email`    | Access user's email address        |

### Additional Scopes

| Scope         | Description                       |
| ------------- | --------------------------------- |
| `guilds`      | Access user's guild (server) list |
| `guilds.join` | Join users to a guild             |
| `connections` | Access user's linked accounts     |

## User Info

Discord returns the following user information:

| Field           | Type    | Description                      |
| --------------- | ------- | -------------------------------- |
| `id`            | string  | Discord user ID (snowflake)      |
| `email`         | string  | User's email address             |
| `username`      | string  | Discord username                 |
| `discriminator` | string  | 4-digit tag (legacy, may be "0") |
| `global_name`   | string  | Display name                     |
| `avatar`        | string  | Avatar hash                      |
| `verified`      | boolean | Whether email is verified        |

### Avatar URL

To construct the avatar URL:

```python
def get_avatar_url(user_id: str, avatar_hash: str) -> str:
    if avatar_hash:
        ext = "gif" if avatar_hash.startswith("a_") else "png"
        return f"https://cdn.discordapp.com/avatars/{user_id}/{avatar_hash}.{ext}"
    # Default avatar
    return f"https://cdn.discordapp.com/embed/avatars/{(int(user_id) >> 22) % 6}.png"
```

## Application setup

Pass `discord` in your configured `providers` list. Follow the shared
[session sign-in or OAuth client setup](/docs/oauth#the-oauth-server) to choose
between cookie sign-in at `/auth/discord/login` and the registered-client PKCE
flow. `/auth/discord/authorize` is only mounted with an `OAuthServer` and
requires a registered client, its redirect URI, and a PKCE challenge.

## Troubleshooting

### "Invalid OAuth2 redirect_uri" Error

- Ensure the redirect URL in Discord Developer Portal matches exactly
- Include the protocol (`https://`)
- No trailing slash unless your app includes one

### Email is None

- The user may not have verified their email on Discord
- Ensure you're requesting the `email` scope

### Rate Limiting

Discord has strict rate limits. If you're getting 429 errors:

- Implement exponential backoff
- Cache user data where possible
