---
title: Social Providers
description: Add social login with GitHub, Google, and other OAuth providers.
order: 4
section: Guides
---

## Overview

Cross-Auth supports social login through OAuth 2.0 providers. Users can sign in
with their existing accounts from services like GitHub and Google, and
Cross-Auth will create or link accounts in your storage.

## How It Works

1. The user clicks "Sign in with GitHub" (or another provider).
2. Your app redirects to the provider's authorization URL.
3. The user authorizes your app.
4. The provider redirects back to your app with an authorization code.
5. Cross-Auth exchanges the code for user info and creates/links the account.

## Account Linking

Cross-Auth supports linking multiple social accounts to a single user. If a user
signs in with GitHub and later connects their Google account, both providers are
linked to the same user record via the `SocialAccount` model.

The `POST /{provider}/link` endpoint handles account linking for authenticated
users.

## Configuration

Each provider requires:

- **Client ID** -- From the provider's developer console.
- **Client Secret** -- From the provider's developer console.
- **Redirect URI** -- The callback URL in your app.

## Hooks

Cross-Auth provides hook events around OAuth social login and account linking.
Use hooks for auditing, telemetry, access checks, and side effects like async
notifications.

```python
from cross_auth import HookRegistration
from cross_auth.fastapi import CrossAuth


def audit_user_info(*, user_info, access_token, provider):
    print("provider", provider.id, "email", user_info.get("email"))


async def notify_login_code(*, code, user, provider, client_id, redirect_uri):
    # async hooks are supported and awaited
    ...


auth = CrossAuth(
    providers=[...],
    storage=secondary_storage,
    accounts_storage=accounts_storage,
    create_token=create_token,
    trusted_origins=["example.com"],
    hooks={
        "after_user_info": [
            HookRegistration(
                callback=audit_user_info,
                priority=50,
                name="audit-user-info",
            ),
        ],
        "after_login_code_issued": [
            HookRegistration(
                callback=notify_login_code,
                timeout_seconds=0.5,
                mode="robust",
            ),
        ],
    },
    hook_settings={
        "mode_by_event": {
            "after_user_info": "robust",
        }
    },
)
```

### Available Events

- `before_token_exchange`
  - Runs before exchanging provider code for tokens.
  - Args: `code`, `proxy_redirect_uri`, `provider_code_verifier`, `provider`,
    `flow`.
- `after_token_exchange`
  - Runs after token exchange succeeds.
  - Args: `token_response`, `provider`, `flow`.
- `before_user_info`
  - Runs before fetching provider user info.
  - Args: `access_token`, `provider`, `flow`.
- `after_user_info`
  - Runs after provider user info is fetched and validated.
  - Args: `user_info`, `access_token`, `provider`.
- `before_account_link`
  - Runs before creating/updating a social account link.
  - Args: `user`, `provider`, `provider_user_id`, `provider_email`, `flow`,
    `action`, `social_account_exists`, `social_account_id`.
- `after_account_link`
  - Runs after creating/updating a social account link.
  - Args: `user`, `provider`, `provider_user_id`, `provider_email`, `flow`,
    `action`, `social_account_exists`, `social_account_id`.
- `after_login_code_issued`
  - Runs after Cross-Auth creates the authorization code for the client app.
  - Args: `code`, `user`, `provider`, `client_id`, `redirect_uri`.

`flow` is `"login"` for regular callback login and `"link"` for manual account
linking (`finalize_link`).

### Error Policy

- `strict` (default): hook exceptions fail the request.
- `robust`: hook exceptions are logged and ignored.

Set per-event defaults with `hook_settings.mode_by_event`, and override per hook
with `HookRegistration(mode="strict" | "robust")`.

### Ordering, Timeouts, and Metadata

- Hooks are ordered by descending `priority` (higher runs first).
- Ties keep declaration order.
- `timeout_seconds` applies to async hooks.
- `name` and `source` are optional metadata included in hook-error logs.

### Payload Mutability

Hook payload mappings/lists/sets are passed as read-only views by default.
Mutating them in hook code raises an error.
