---
title: GitHub
description: Configure GitHub OAuth for authentication
section: Providers
order: 4
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

GitHub reports whether the user's primary email is verified. Linking a GitHub
sign-in to an existing user by email requires a verified primary email; see
[Linking by email](/docs/social-providers#linking-by-email).

## GitHub Setup

### Create an OAuth App

1. Go to [GitHub Settings](https://github.com/settings/developers) → **Developer
   settings** → **OAuth Apps**
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

| Feature              | OAuth App      | GitHub App             |
| -------------------- | -------------- | ---------------------- |
| User authentication  | Yes            | Yes                    |
| Repository access    | Via user token | Via installation token |
| Granular permissions | No             | Yes                    |
| Webhooks             | No             | Yes                    |

For simple authentication, **OAuth Apps** are sufficient and simpler to set up.
Use GitHub Apps if you need repository access or webhooks.

## Scopes

The GitHub provider requests the `user:email` scope by default, which provides:

- Access to the user's public profile
- Access to the user's email addresses, including private and unverified ones

### Available Scopes

| Scope        | Description                           |
| ------------ | ------------------------------------- |
| `user:email` | Read user's email addresses (default) |
| `read:user`  | Read all user profile data            |
| `user`       | Read and write user profile data      |

## User Info

Cross Auth starts with GitHub's `/user` response and looks up `/user/emails` to
select the primary email:

| UserInfo field   | Source                                                 |
| ---------------- | ------------------------------------------------------ |
| `id`             | GitHub's numeric user ID (stored as a string identity) |
| `email`          | Primary email, falling back to the profile email       |
| `email_verified` | Primary email's `verified` flag, which may be `False`  |
| `name`           | Display name, falling back to the `login` username     |

The primary email is not necessarily verified. If the email lookup fails or has
no primary entry, the profile email and any profile verification status remain
the fallback; verification may be unknown (`None`). Linking by email still
requires a verified address under the configured trust policy.

Provider-specific keys such as `login` and `avatar_url` remain in the returned
profile dictionary, but are not part of the standard `UserInfo` contract or
automatically persisted as user fields.

## Application setup

Pass `github` in your configured `providers` list. Follow the shared
[session sign-in or OAuth client setup](/docs/oauth#the-oauth-server) to choose
between cookie sign-in at `/auth/github/login` and the registered-client PKCE
flow. `/auth/github/authorize` is only mounted with an `OAuthServer` and
requires a registered client, its redirect URI, and a PKCE challenge.

## Troubleshooting

### "Bad credentials" Error

- Verify your client secret is correct
- Regenerate the client secret if needed

### Email is None

- Request the `user:email` scope (included by default) so Cross Auth can fetch
  the primary email even when it is private
- If the email lookup fails and no public profile email exists, email is `None`
- An unverified primary email is returned with `email_verified=False`, not
  silently discarded
