---
title: GitHub
description: Configure GitHub OAuth for authentication
section: Providers
order: 3
---

# GitHub

GitHub uses standard OAuth 2.0 with a userinfo endpoint to fetch user data.

## Configuration

```python
from cross_auth.social_providers.github import GitHubProvider

github = GitHubProvider(
    client_id="your-github-client-id",
    client_secret="your-github-client-secret",
)
```

## GitHub Setup

### Create an OAuth App

1. Go to [GitHub Settings](https://github.com/settings/developers) → **Developer settings** → **OAuth Apps**
2. Click **New OAuth App**
3. Fill in the application details:
   - **Application name**: Your app name
   - **Homepage URL**: `https://your-app.com`
   - **Authorization callback URL**: `https://your-app.com/auth/github/callback`
4. Click **Register application**
5. Copy the **Client ID**
6. Click **Generate a new client secret** and copy it

### GitHub Apps vs OAuth Apps

GitHub offers two types of apps:

| Feature | OAuth App | GitHub App |
|---------|-----------|------------|
| User authentication | Yes | Yes |
| Repository access | Via user token | Via installation token |
| Granular permissions | No | Yes |
| Webhooks | No | Yes |

For simple authentication, **OAuth Apps** are sufficient and simpler to set up. Use GitHub Apps if you need repository access or webhooks.

## Scopes

The GitHub provider requests the `user:email` scope by default, which provides:

- Access to the user's public profile
- Access to the user's verified email addresses

### Available Scopes

| Scope | Description |
|-------|-------------|
| `user:email` | Read user's email addresses (default) |
| `read:user` | Read all user profile data |
| `user` | Read and write user profile data |

## User Info

GitHub returns the following user information:

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | GitHub user ID |
| `email` | string | Primary verified email |
| `login` | string | GitHub username |
| `name` | string | Display name |
| `avatar_url` | string | Profile picture URL |

## Example

```python
from fastapi import FastAPI
from cross_auth.router import AuthRouter
from cross_auth.social_providers.github import GitHubProvider

github = GitHubProvider(
    client_id="Iv1.abc123",
    client_secret="secret123",
)

auth_router = AuthRouter(
    providers=[github],
    # ... other config
)

app = FastAPI()
app.include_router(auth_router, prefix="/auth")
```

Users can then authenticate via:
- `GET /auth/github/authorize` - Start OAuth flow
- `GET /auth/github/callback` - OAuth callback (handled automatically)

## Troubleshooting

### "Bad credentials" Error

- Verify your client secret is correct
- Regenerate the client secret if needed

### Email is None

- The user may not have a public email set
- The user may not have verified their email
- Request the `user:email` scope (included by default)
