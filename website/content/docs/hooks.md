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
    storage=secondary_storage,
    accounts_storage=accounts_storage,
    session_storage=session_storage,
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
- Session and account hooks (`authenticate`, `login`, `logout`, `user.create`,
  `social_account.create`, `social_account.update`) are synchronous. OAuth and
  token hooks may be synchronous or asynchronous.
- Hook events use framework-neutral `cross_web` request and response objects at
  the hook boundary.
- Do not enforce security policy in an `after` hook. If an operation should be
  blocked, raise `CrossAuthException` from the matching `before` hook.
- `before` hooks cannot change an identity Cross-Auth has already established:
  the provider, the verified `provider_user_id`, `email`, and `email_verified`
  claims, and the raw `id`, `email`, and `email_verified` keys of `user_info` in
  OAuth callback and finalize-link hooks; the resolved `email`,
  `email_verified`, and those raw `user_info` keys in `user.create`; the
  signed-in user in link, finalize-link, password-grant, and `login` hooks; and
  a social account's owner, provider identity, `is_login_method`,
  `provider_email`, `provider_email_verified`, and raw `user_info` keys. Hooks
  can read these values to deny an operation. Canonicalize emails with the
  `normalize_email` callback passed to `CrossAuth`.
- `before` hooks receive read-only records from `cross_auth.hooks` instead of
  the live provider and stored objects: `ProviderSnapshot` (`id`,
  `trust_email`), `UserSnapshot` (`id`, `email`, `email_verified`), and
  `SocialAccountSnapshot` (`id`, `user_id`, `provider`, `provider_user_id`,
  `provider_email`, `provider_email_verified`, `is_login_method`).
  `validated_user_info` is a frozen `ValidatedUserInfo`. Assigning to any of
  them raises `dataclasses.FrozenInstanceError`. Returning an event that changes
  an established identity raises `ValueError` before anything is resolved or
  saved, and policy-only before hooks (`oauth.link`, `oauth.disconnect`,
  `token.password`, `token.authorization_code`) raise `TypeError` for any
  returned event. `after` hooks still receive the stored objects.
- These rules cover the data Cross-Auth passes to hooks. Hooks are trusted
  application code: Cross-Auth does not sandbox or undo a hook that changes
  global state, writes to storage directly, or calls an external service, even
  when the hook then raises.
- Hook exceptions propagate, including exceptions from `after` hooks. An `after`
  hook runs once the operation has succeeded, so its failure cannot undo it: a
  session that was already saved stays saved. Catch and report errors from
  non-critical work (notifications, analytics) yourself, or enqueue that work.
- `after` hooks for a write run once the storage that owns the write has
  committed it. Cross-Auth hands each hook to that storage's `on_commit`: the
  accounts storage for user and social-account changes (`user.create`,
  `social_account.*`, `oauth.id_token`, `oauth.finalize_link`,
  `oauth.disconnect`), and the session storage for `login`, `logout`, and the
  browser `oauth.callback` and `token.*` events that issue a session. Built-in
  adapters commit each operation before returning, so their hooks run
  immediately, in the order shown on this page. An adapter whose writes join
  your application's transaction runs them after the outermost transaction
  commits and drops them on rollback. Hooks after a custom `token_issuer` run
  when the issuer returns. `authenticate` writes nothing, and `oauth.authorize`
  and `oauth.link` follow secondary-storage writes that have already completed,
  so their hooks run immediately.
- Accounts, sessions, secondary storage, and a custom `token_issuer` commit
  separately; a login is not one transaction across them. `user.create` and
  `social_account.create` run as one callback after signup, so a failing
  `user.create` hook still stops the next one. An after hook that fails stops
  the hooks after it but does not undo the commit, and nothing retries it. Hooks
  run in the request process: a crash after commit loses them, so use an outbox
  written in the same transaction when delivery must be reliable.
- Secondary storage (OAuth state, authorization codes, link codes) completes
  each operation before returning. Rolling back accounts or sessions does not
  restore a code that was already consumed.
- The browser sign-in flow raises `RuntimeError` instead of issuing a session or
  authorization code while account changes are uncommitted (an accounts storage
  that deferred `on_commit` callbacks). Do not run it inside an application
  transaction.
- Cookie logins (`auth.login()` and browser sign-in) and a `logout` that revokes
  a session raise `RuntimeError` before writing anything, or changing the
  response, when the session storage defers `on_commit` callbacks: their after
  hooks may change the response, which is built before an application
  transaction could commit. A `logout` without a session writes nothing, so its
  after hook runs immediately.
- A bearer session (`auth.issue_session_token()`, `/token`) from a session
  storage that defers callbacks is issued before it is committed. Commit before
  you deliver the token; after a rollback the token does not work and no success
  hooks run.
- Keep slow side effects out of the request path. Queue email, analytics, and
  webhook work from the hook when possible.

## Real-World Use Cases

Use this as a quick guide when deciding where custom logic belongs.

| Hook                       | Use it when you need to...                                              | Common `before` work                                                                                        | Common `after` work                                                                      |
| -------------------------- | ----------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| `authenticate`             | Customize password-based sign-in checks before a session is created     | Normalize email addresses, block specific accounts, enforce tenant-specific password login rules            | Audit successful and failed password authentication attempts                             |
| `login`                    | Control every cookie or bearer login before its credential is issued    | Block login for service or suspended users, clamp session lifetimes, adjust the cookie login response       | Audit logins, add headers or cookies, publish "user logged in" telemetry                 |
| `logout`                   | Control session deletion and post-logout side effects                   | Require an active session, prevent logout in special flows, capture session context before deletion         | Audit logout activity, revoke related application state, trigger notifications           |
| `user.create`              | Apply policy and side effects around creation of a local user           | Enforce signup eligibility or invitation requirements                                                       | Send welcome events, create telemetry, start post-signup provisioning                    |
| `social_account.create`    | Customize and observe creation of a provider account                    | Add app-specific storage fields, normalize provider metadata, block creation                                | Audit new linked accounts, trigger downstream provisioning                               |
| `social_account.update`    | Customize and observe updates to an existing provider account           | Refresh app-specific storage fields, normalize provider metadata, block an update                           | Audit linked-account changes, trigger downstream metadata updates                        |
| `oauth.authorize`          | Shape the outbound OAuth authorization request                          | Attach tenant-specific login hints, require extra app-level context, normalize provider-facing request data | Track provider redirects, record generated state values for observability                |
| `oauth.callback`           | Inspect provider user data before Cross-Auth creates or finds a user    | Enforce email domain restrictions, reject unverified emails, apply provider-specific access rules           | Provision internal profiles, send first-login events, audit newly created users          |
| `oauth.link`               | Control whether an already-authenticated user may start account linking | Restrict linking by role, plan, tenant, or email domain                                                     | Track linking attempts, log provider selection, store link-start telemetry               |
| `oauth.finalize_link`      | Validate the provider account before it is attached to the current user | Disallow login-on-link, reject conflicting identities, require extra provider claims                        | Audit successful links, sync linked account metadata, trigger downstream account updates |
| `oauth.disconnect`         | Control provider-account disconnection for an authenticated user        | Block disconnects for policy reasons, enforce plan or tenant rules                                          | Revoke provider tokens, clear provider caches, audit disconnected accounts               |
| `token.password`           | Control OAuth password grant issuance for API clients                   | Disable password grant for some clients, enforce API client policy, reject risky usernames                  | Audit token issuance, increment metrics, notify legacy-client usage                      |
| `token.authorization_code` | Control authorization-code token exchange for OAuth clients             | Check user entitlement or requested scope, add final policy checks before issuing tokens                    | Audit code exchanges, record user/client pairs, emit token issuance telemetry            |

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

Runs once around every login that issues a credential, after Cross-Auth already
knows which user is being signed in:

| Entry point                                     | `credential` | Credential issued                                 |
| ----------------------------------------------- | ------------ | ------------------------------------------------- |
| Browser OAuth session callback, `auth.login()`  | `"cookie"`   | A session and its cookie on `response`            |
| `auth.issue_session_token()`                    | `"bearer"`   | A session; its token is returned to your code     |
| `auth.sign_in_with_id_token()`                  | `"bearer"`   | A session; its token is returned to your code     |
| `/token` password and authorization-code grants | `"bearer"`   | A session, or the token your `token_issuer` mints |

For `/token`, the `login` hooks run inside the `token.password` or
`token.authorization_code` hooks. Creating an authorization code in the browser
callback is not a login; redeeming it at `/token` is. Resolving the user of a
native `id_token` without a session (`resolve_id_token_user`), connecting or
linking an account, and refreshing a sliding session are not logins either.

`BeforeLoginEvent` carries `user_id`, `credential`, `login_method`, `max_age`,
`metadata`, and `response`. A `before` hook can deny the login by raising, or
return an updated event to change `login_method`, `max_age`, `metadata`, or the
cookie login `response`. It cannot change who logs in: returning a different
`user_id` (or `credential`, or adding/removing `response`) raises `ValueError`
and nothing is issued. When a `token_issuer` mints the credential, Cross-Auth
creates no session: `max_age` and `metadata` are `None`, and setting either
raises `ValueError` because Cross-Auth cannot apply them. Your issuer decides
its token's lifetime and claims; the hooks can still deny the login before the
issuer is called.

`login_method` says how the user signed in: the provider id for a browser OAuth
sign-in, an authorization code or `sign_in_with_id_token`, `"password"` for the
password grant, or what your code passed to `auth.login()` or
`auth.issue_session_token()` (`None` if nothing). It is set on every login,
including those a `token_issuer` mints. The value a `before` hook approves is
what the session records, or what the issuer receives as
`TokenIssueRequest.login_method`, and what `AfterLoginEvent.login_method`
reports.

`AfterLoginEvent` carries `user_id`, `credential`, `login_method`, `response`
(cookie logins only), and `session_record`, which is `None` when a
`token_issuer` minted the credential. The raw session token is never exposed to
hooks. It runs once the session storage commits the new session, or as soon as
your `token_issuer` returns: Cross-Auth cannot see a transaction inside the
issuer, so an issuer that stores tokens must commit before returning.

```python
from dataclasses import replace

from cross_auth.hooks import AfterLoginEvent, BeforeLoginEvent


@auth.before("login")
def apply_login_policy(event: BeforeLoginEvent) -> BeforeLoginEvent | None:
    if event.user_id in suspended_users:
        raise CrossAuthException("access_denied", "Account suspended", 403)
    if event.login_method == "password" and event.user_id in sso_only_users:
        raise CrossAuthException("access_denied", "Sign in with SSO", 403)
    if event.max_age is not None and event.max_age > MAX_SESSION_TTL:
        return replace(event, max_age=MAX_SESSION_TTL)
    return None


@auth.after("login")
def audit_login(event: AfterLoginEvent) -> None:
    if event.response is not None:
        event.response.headers = {
            **(event.response.headers or {}),
            "X-Session-User": event.user_id,
        }
    metrics.increment(
        "login",
        tags={"credential": event.credential, "method": event.login_method},
    )
```

### `logout`

Runs around session revocation by `auth.logout()` and the mounted `POST /logout`
route. Use it to inspect the session before it is revoked, then record logout
activity or clean up related application state after revocation succeeds.

The before event carries the active `session_record` Cross-Auth resolved from
the session cookie or `Authorization: Bearer` header. It is `None` when the
request has no token, or one that is unknown, expired, or revoked. A before hook
that raises `CrossAuthException` stops the logout, and the route answers with
that error instead of 204.

Both events carry the `scope`: `"current"` revokes the request's session and
`"all"` every session of its user. A before hook may return a different scope,
for example to refuse logging out everywhere for some accounts. The after
event's `revoked_count` is the number of sessions the logout revoked: `0`
without a session, `1` for `"current"`.

```python
from dataclasses import replace

from cross_auth.hooks import AfterLogoutEvent, BeforeLogoutEvent


@auth.before("logout")
def keep_admins_signed_in_elsewhere(
    event: BeforeLogoutEvent,
) -> BeforeLogoutEvent | None:
    if event.scope == "all" and is_admin_session(event.session_record):
        return replace(event, scope="current")
    return None


@auth.after("logout")
def audit_logout(event: AfterLogoutEvent) -> None:
    session_id = None if event.session_record is None else event.session_record.id
    audit_log.record("session_logout", session_id=session_id)
```

## Account Hooks

### `user.create`

Runs only when Cross-Auth is about to create a new local user. The `before` hook
contains the resolved email fields, raw provider `user_info`, and app-specific
`extra_fields`. It may abort by raising `CrossAuthException` or return a
replacement event to add fields required by your user model. `email` (already
canonicalized by `normalize_email`), `email_verified`, and the `id`, `email`,
and `email_verified` keys of `user_info` are read-only; other `user_info` keys
are profile metadata. The `after` hook runs after the storage implementation has
committed both the user and provider identity, including required application
rows, and receives the created user. It runs before
`after social_account.create`. Neither after-create hook runs if signup rolls
back.

Use after hooks for external work such as welcome emails or billing requests. If
an after hook fails, the committed signup remains saved; the request can fail
without undoing it. Delivery retries are application-owned. If delivery must
survive a process crash, save an outbox row in the signup transaction and
process it separately.

```python
from dataclasses import replace

from cross_auth.hooks import AfterUserCreateEvent, BeforeUserCreateEvent


@auth.before("user.create")
def require_invite(event: BeforeUserCreateEvent) -> None:
    if not invitations.contains(event.email):
        raise CrossAuthException("signup_not_allowed", "Invite only", 403)


@auth.before("user.create")
def store_full_name(event: BeforeUserCreateEvent) -> BeforeUserCreateEvent:
    return replace(
        event,
        extra_fields={**event.extra_fields, "full_name": event.user_info["name"]},
    )


@auth.after("user.create")
def track_created_user(event: AfterUserCreateEvent) -> None:
    analytics.capture("account_created", user_id=str(event.user.id))
```

`extra_fields` cannot replace `email` or `email_verified`. Built-in SQLModel
storage validates and writes extra fields as mapped columns. Custom
`AccountsStorage` implementations receive the mapping in the `user` argument to
`create_user_with_identity` and decide how to persist it.

### `social_account.create` and `social_account.update`

These hooks run around every social-account create and update, including browser
OAuth, native ID-token sign-in, connect, and finalize-link flows. The `before`
events contain the resolved standard fields and raw provider `user_info`; the
update event also contains a `SocialAccountSnapshot` of the existing account.
Return a replacement event to alter writable token/profile fields or add
app-specific `extra_fields`. `user_id`, `provider`, `provider_user_id`,
`is_login_method`, `provider_email`, `provider_email_verified`, the `id`,
`email`, and `email_verified` keys of `user_info`, and, for updates, the
`social_account` snapshot are read-only: changing them raises `ValueError` and
nothing is written. On update, `provider_email` and `provider_email_verified`
carry the provider's current claims, so a provider-verified email change still
refreshes the stored account. Control a requested promotion through
`allow_login` in the `before oauth.finalize_link` hook. The after-update event
contains the saved account, including any promotion. The built-in SQLModel
adapter validates and writes the extra columns.

Stack the two decorators when the same handler applies to both operations. The
event's literal `operation` field remains available to shared handlers.

```python
from dataclasses import replace

from cross_auth.hooks import (
    AfterSocialAccountCreateEvent,
    AfterSocialAccountUpdateEvent,
    BeforeSocialAccountCreateEvent,
    BeforeSocialAccountUpdateEvent,
)


@auth.before("social_account.create")
@auth.before("social_account.update")
def store_provider_username(
    event: BeforeSocialAccountCreateEvent | BeforeSocialAccountUpdateEvent,
) -> BeforeSocialAccountCreateEvent | BeforeSocialAccountUpdateEvent:
    username = (
        event.user_info.get("login") or event.provider_email or event.provider_user_id
    )
    return replace(
        event,
        extra_fields={**event.extra_fields, "provider_username": username},
    )


@auth.after("social_account.create")
@auth.after("social_account.update")
def audit_social_account_change(
    event: AfterSocialAccountCreateEvent | AfterSocialAccountUpdateEvent,
) -> None:
    audit_log.record(
        f"social_account_{event.operation}d",
        operation=event.operation,
        social_account_id=str(event.social_account.id),
    )
```

`extra_fields` cannot replace a standard field; use its dedicated event field
when it is writable. Custom `AccountsStorage` implementations receive
`extra_fields` on `create_social_account` and `update_social_account` and decide
how to persist them.

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
creates or finds the local user. Use it to enforce provider-claim policy or to
adjust raw `user_info` profile data, then provision profiles or audit newly
connected provider accounts after success. The provider (a `ProviderSnapshot`)
and `validated_user_info` (`provider_user_id`, `email`, `email_verified`) select
and link the account and cannot be changed. Nor can the raw `id`, `email`, and
`email_verified` keys of `user_info`, which storage adapters may read when
creating users; other `user_info` keys are profile metadata.

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
record link-start telemetry once Cross-Auth creates the linking state. The
before event carries a `UserSnapshot` and a `ProviderSnapshot`. This before hook
is policy-only and must return `None`.

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
identities, adjust raw `user_info` profile data, or disable login-on-link, then
sync metadata after the link succeeds. The signed-in `user` (a `UserSnapshot`),
the provider (a `ProviderSnapshot`), `validated_user_info`, and the raw `id`,
`email`, and `email_verified` keys of `user_info` cannot be changed.

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

### `oauth.disconnect`

Runs around `DELETE /{provider}/social-accounts` and
`DELETE /{provider}/social-accounts/{social_account_id}`, after Cross-Auth has
found the selected provider account, verified it belongs to the current user,
and before the storage transaction starts. Use the before hook to block
app-specific cases. Storage then rereads the current credentials and atomically
checks that deleting a login-enabled account leaves a usable password or another
login-enabled account. Changes made while the before hook runs are included in
that check.

The after hook runs only after deletion commits. It does not run when storage
rejects the deletion or rolls back. Use it for external cleanup, such as
provider token revocation. The before event carries `ProviderSnapshot`,
`UserSnapshot`, and `SocialAccountSnapshot` records. The before hook is
policy-only and must return `None`.

```python
from cross_auth.hooks import (
    AfterOAuthDisconnectEvent,
    BeforeOAuthDisconnectEvent,
)


@auth.before("oauth.disconnect")
async def require_disconnect_enabled(event: BeforeOAuthDisconnectEvent) -> None:
    if event.provider.id == "github" and not settings.ALLOW_GITHUB_DISCONNECT:
        raise CrossAuthException(
            "forbidden",
            "GitHub disconnect is disabled",
            403,
        )


@auth.after("oauth.disconnect")
async def cleanup_provider_state(event: AfterOAuthDisconnectEvent) -> None:
    audit_log.record(
        "oauth_disconnected",
        user_id=str(event.user.id),
        provider=event.provider.id,
        social_account_id=str(event.social_account.id),
    )
```

## Token Hooks

### `token.password`

Runs around OAuth password-grant token issuance. The password grant is
[deprecated](/docs/oauth#password-grant-deprecated); use this hook to restrict
which clients may still exchange usernames and passwords for tokens, then audit
or measure the clients that remain. It only runs when the application opts in
with `OAuthServer(password_grant=True)`; without that, `/token` refuses the
grant before any hook. The before event's `user` is a `UserSnapshot`, or `None`
when no user matches the username. This before hook is policy-only and must
return `None`.

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
