---
title: Security Best Practices
description: Keep your authentication secure
section: Advanced
order: 2
---

# Security Best Practices

Follow these guidelines to keep your authentication implementation secure.

## Environment Variables

Never hardcode credentials:

```python
import os
from cross_auth.social_providers import GitHubProvider

github = GitHubProvider(
    client_id=os.getenv("GITHUB_CLIENT_ID"),
    client_secret=os.getenv("GITHUB_CLIENT_SECRET"),
    redirect_uri=os.getenv("GITHUB_REDIRECT_URI")
)
```

## HTTPS Only

Always use HTTPS in production:

```python
# Enforce HTTPS redirect URIs
redirect_uri="https://your-app.com/auth/callback/github"
```

## Token Storage

Store tokens securely:

- Use encrypted database fields
- Never log tokens
- Implement token rotation
- Set appropriate expiration times

## State Parameter

Cross Auth automatically includes a state parameter to prevent CSRF attacks. This is handled transparently.

## Scope Limitation

Only request the scopes you actually need:

```python
github = GitHubProvider(
    # ... other config
    scopes=["user:email"]  # Minimal scopes
)
```
