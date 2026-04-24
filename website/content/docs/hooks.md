---
title: Hooks
description: Extend Cross-Auth with typed lifecycle hooks.
order: 6
section: Guides
---

## Overview

Cross-Auth supports typed instance hooks on `CrossAuth`:

- `@auth.before(event)` runs before the lifecycle step
- `@auth.after(event)` runs after the lifecycle step succeeds

Before hooks can abort by raising `CrossAuthException`. Some before events also
support returning a new event object created with `dataclasses.replace()` for
explicitly mutable fields. After hooks are for side effects only and must return
`None`.

## Setup

```python
from dataclasses import replace

from cross_auth.exceptions import CrossAuthException
from cross_auth.fastapi import CrossAuth

auth = CrossAuth(
    providers=[],
    storage=session_storage,
    accounts_storage=accounts_storage,
    create_token=lambda _: ("", 0),
    trusted_origins=["https://myapp.com"],
)
```

The examples below use app-level services such as `audit_log`, `metrics`,
`tenants`, `profiles`, and `emails`. Replace those with your own database,
queue, or observability code.

## Hook Behavior

- Use `before` hooks for policy decisions and for the small set of explicitly
  mutable event fields documented below.
- Use `after` hooks for post-success work such as audit logs, metrics, welcome
  emails, or provisioning records.
- Session hooks (`authenticate`, `login`, `logout`) are synchronous. OAuth and
  token hooks may be synchronous or asynchronous.
- Hook events use framework-neutral `cross_web` request and response objects at
  the hook boundary.
- Do not enforce security policy in an `after` hook. If an operation should be
  blocked, raise `CrossAuthException` from the matching `before` hook.
- Keep slow side effects out of the request path. Queue email, analytics, and
  webhook work from the hook when possible.

## Real-World Use Cases

Use this as a quick guide when deciding where custom logic belongs.

| Hook                       | Use it when you need to...                                                   | Common `before` work                                                                                        | Common `after` work                                                                      |
| -------------------------- | ---------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| `authenticate`             | Customize password-based sign-in checks before a session is created          | Normalize email addresses, block specific accounts, enforce tenant-specific password login rules            | Audit successful and failed password authentication attempts                             |
| `login`                    | Control browser session creation and the HTTP response used for session auth | Block session login for service users, remap temporary IDs, add request-scoped policy checks                | Add headers or cookies, publish "user logged in" telemetry                               |
| `logout`                   | Control session deletion and post-logout side effects                        | Require an active session, prevent logout in special flows, capture session context before deletion         | Audit logout activity, revoke related application state, trigger notifications           |
| `oauth.authorize`          | Shape the outbound OAuth authorization request                               | Attach tenant-specific login hints, require extra app-level context, normalize provider-facing request data | Track provider redirects, record generated state values for observability                |
| `oauth.callback`           | Inspect provider user data before Cross-Auth creates or finds a user         | Enforce email domain restrictions, reject unverified emails, apply provider-specific access rules           | Provision internal profiles, send first-login events, audit newly created users          |
| `oauth.link`               | Control whether an already-authenticated user may start account linking      | Restrict linking by role, plan, tenant, or email domain                                                     | Track linking attempts, log provider selection, store link-start telemetry               |
| `oauth.finalize_link`      | Validate the provider account before it is attached to the current user      | Disallow login-on-link, reject conflicting identities, require extra provider claims                        | Audit successful links, sync linked account metadata, trigger downstream account updates |
| `token.password`           | Control OAuth password grant issuance for API clients                        | Disable password grant for some clients, enforce API client policy, reject risky usernames                  | Audit token issuance, increment metrics, notify legacy-client usage                      |
| `token.authorization_code` | Control authorization-code token exchange for OAuth clients                  | Check user entitlement or requested scope, add final policy checks before issuing tokens                    | Audit code exchanges, record user/client pairs, emit token issuance telemetry            |

## Session Hooks

### `authenticate`

Runs around password authentication before a browser session or OAuth token is
created. Use it to normalize credentials, block password login for specific
accounts, and audit whether Cross-Auth found a matching user.

```python
from cross_auth.hooks import AfterAuthenticateEvent, BeforeAuthenticateEvent


@auth.before("authenticate")
def normalize_email(event: BeforeAuthenticateEvent) -> BeforeAuthenticateEvent:
    return replace(event, email=event.email.strip().lower())


@auth.after("authenticate")
def audit_authenticate(event: AfterAuthenticateEvent) -> None:
    audit_log.record(
        "password_authentication",
        email=event.email,
        user_id=None if event.user is None else str(event.user.id),
        succeeded=event.user is not None,
    )
```

### `login`

Runs around browser session creation after you already know which user should be
signed in. Use it to enforce session-specific policy, adjust the login response,
and emit successful login telemetry.

```python
from cross_auth.hooks import AfterLoginEvent, BeforeLoginEvent


@auth.before("login")
def block_service_user_login(event: BeforeLoginEvent) -> None:
    if event.user_id.startswith("svc_"):
        raise CrossAuthException(
            "forbidden",
            "Service users cannot create browser sessions",
            403,
        )


@auth.after("login")
def add_login_header(event: AfterLoginEvent) -> None:
    event.response.headers = {
        **(event.response.headers or {}),
        "X-Session-User": event.user_id,
    }
    metrics.increment("session.login.created")
```

### `logout`

Runs around browser session deletion. Use it to require or inspect the active
session before it is removed, then record logout activity or clean up related
application state after deletion succeeds.

```python
from cross_auth.hooks import AfterLogoutEvent, BeforeLogoutEvent


@auth.before("logout")
def require_active_session(event: BeforeLogoutEvent) -> None:
    if event.session_id is None:
        raise CrossAuthException("unauthorized", "No active session", 401)


@auth.after("logout")
def audit_logout(event: AfterLogoutEvent) -> None:
    audit_log.record("session_logout", session_id=event.session_id)
```

## OAuth Hooks

### `oauth.authorize`

Runs while building the outbound provider authorization redirect. Cross-Auth
already validates OAuth client fields such as `client_id`, `redirect_uri`, and
PKCE parameters; use this hook for application-specific request policy or to
customize the provider-facing `login_hint` before redirecting the browser. Only
`login_hint` is replaceable from this before hook.

```python
from cross_auth.hooks import AfterOAuthAuthorizeEvent, BeforeOAuthAuthorizeEvent


@auth.before("oauth.authorize")
async def apply_tenant_login_hint(
    event: BeforeOAuthAuthorizeEvent,
) -> BeforeOAuthAuthorizeEvent | None:
    tenant = event.request.query_params.get("tenant")
    if tenant is None:
        return None

    domain = await tenants.primary_email_domain(tenant)
    if domain is None:
        raise CrossAuthException("access_denied", "Unknown tenant", 400)

    return replace(event, login_hint=f"user@{domain}")


@auth.after("oauth.authorize")
async def track_authorize(event: AfterOAuthAuthorizeEvent) -> None:
    metrics.increment(
        "oauth.authorize.redirect",
        tags={"provider": event.provider.id, "client_id": event.client_id},
    )
```

### `oauth.callback`

Runs after the OAuth provider returns user information and before Cross-Auth
creates or finds the local user. Use it to enforce provider-claim policy, or to
replace `user_info` / `validated_user_info` for provider claim normalization,
then provision profiles or audit newly connected provider accounts after
success.

```python
from cross_auth.hooks import AfterOAuthCallbackEvent, BeforeOAuthCallbackEvent


@auth.before("oauth.callback")
async def require_company_email(
    event: BeforeOAuthCallbackEvent,
) -> None:
    email = event.validated_user_info.email
    if email is None or not email.endswith("@example.com"):
        raise CrossAuthException("access_denied", "Company email required", 400)

    if event.validated_user_info.email_verified is not True:
        raise CrossAuthException(
            "access_denied",
            "Verified provider email required",
            400,
        )


@auth.after("oauth.callback")
async def provision_new_oauth_user(event: AfterOAuthCallbackEvent) -> None:
    if event.created_user is not None:
        await profiles.create_default_workspace(event.created_user.id)
        emails.enqueue_welcome(event.created_user.email)

    if event.created_social_account is not None:
        audit_log.record(
            "oauth_account_created",
            user_id=str(event.user.id),
            provider=event.provider.id,
            provider_user_id=event.created_social_account.provider_user_id,
        )
```

For browser session callbacks, `event.authorization_code`, `event.redirect_uri`,
and `event.client_state` are `None`. Those fields are populated for OAuth
authorization-code client flows.

### `oauth.link`

Runs when an authenticated user starts linking another OAuth provider account.
Use it to decide whether the current user is allowed to begin linking, then
record link-start telemetry once Cross-Auth creates the linking state. This
before hook is policy-only and must return `None`.

```python
from cross_auth.hooks import AfterOAuthLinkEvent, BeforeOAuthLinkEvent


@auth.before("oauth.link")
async def allow_only_company_users(event: BeforeOAuthLinkEvent) -> None:
    if not event.user.email.endswith("@example.com"):
        raise CrossAuthException(
            "forbidden",
            "Linking is restricted to company accounts",
            403,
        )


@auth.after("oauth.link")
async def audit_link_start(event: AfterOAuthLinkEvent) -> None:
    audit_log.record(
        "oauth_link_started",
        user_id=str(event.user.id),
        provider=event.provider.id,
        state=event.state,
    )
```

### `oauth.finalize_link`

Runs after the provider returns account data for a link flow and before that
provider account is attached to the signed-in user. Use it to reject conflicting
identities, replace provider claim data, or disable login-on-link, then sync
metadata after the link succeeds.

```python
from cross_auth.hooks import (
    AfterOAuthFinalizeLinkEvent,
    BeforeOAuthFinalizeLinkEvent,
)


@auth.before("oauth.finalize_link")
async def require_same_email_for_link(
    event: BeforeOAuthFinalizeLinkEvent,
) -> BeforeOAuthFinalizeLinkEvent:
    provider_email = event.validated_user_info.email
    if provider_email != event.user.email:
        raise CrossAuthException(
            "forbidden",
            "Linked provider email must match the signed-in user",
            403,
        )

    return replace(event, allow_login=False)


@auth.after("oauth.finalize_link")
async def audit_link_complete(event: AfterOAuthFinalizeLinkEvent) -> None:
    audit_log.record(
        "oauth_link_completed",
        user_id=str(event.user.id),
        provider=event.provider.id,
        social_account_id=str(event.social_account.id),
        created=event.created_social_account is not None,
    )
```

## Token Hooks

### `token.password`

Runs around OAuth password-grant token issuance. Use it to restrict which
clients may exchange usernames and passwords for tokens, then audit or measure
successful token issuance. This before hook is policy-only and must return
`None`.

```python
from cross_auth.hooks import AfterTokenPasswordEvent, BeforeTokenPasswordEvent


@auth.before("token.password")
async def block_password_grant_for_legacy_spa(
    event: BeforeTokenPasswordEvent,
) -> None:
    if event.client_id == "legacy-spa":
        raise CrossAuthException(
            "unauthorized_client",
            "Password grant disabled for this client",
            400,
        )


@auth.after("token.password")
async def audit_password_grant(event: AfterTokenPasswordEvent) -> None:
    audit_log.record(
        "password_token_issued",
        client_id=event.client_id,
        user_id=str(event.user.id),
        username=event.username,
    )
```

### `token.authorization_code`

Runs around OAuth authorization-code token exchange. Cross-Auth already checks
the code, redirect URI, client ID, expiry, and PKCE verifier; use this hook for
application-specific user or scope policy before issuing tokens. This before
hook is policy-only and must return `None`.

```python
from cross_auth.hooks import (
    AfterTokenAuthorizationCodeEvent,
    BeforeTokenAuthorizationCodeEvent,
)


@auth.before("token.authorization_code")
async def enforce_auth_code_token_policy(
    event: BeforeTokenAuthorizationCodeEvent,
) -> None:
    if await profiles.is_suspended(event.user_id):
        raise CrossAuthException(
            "invalid_grant",
            "User is not allowed to receive tokens",
            400,
        )

    requested_scopes = set((event.scope or "").split())
    if "offline_access" in requested_scopes:
        raise CrossAuthException(
            "invalid_scope",
            "Offline access is not enabled",
            400,
        )


@auth.after("token.authorization_code")
async def audit_auth_code_grant(
    event: AfterTokenAuthorizationCodeEvent,
) -> None:
    audit_log.record(
        "authorization_code_token_issued",
        client_id=event.authorization_data.client_id,
        user_id=event.authorization_data.user_id,
    )
```
