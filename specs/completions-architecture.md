# Completions Architecture

**Status:** current.

## The core split

```text
             ┌──────────────────────────────────────┐
             │   AuthCompletion (one per transport) │
             │   • entry_path(provider_id)          │
             │   • start(request, context, provider)│
             │   • complete(...)                    │
             │   • on_failure(...)                  │
             │   • extra_routes(providers)          │
             └───────────────┬──────────────────────┘
                             │
             ┌───────────────┴──────────────────────┐
             │        AuthRouter (dispatcher)       │
             │   per provider × completion:         │
             │     entry route (completion.start)   │
             │   per provider:                      │
             │     one /callback, dispatches by     │
             │     flow_state.kind                  │
             └───────────────┬──────────────────────┘
                             │
             ┌───────────────┴──────────────────────┐
             │  OAuth2Provider (pure strategy)      │
             │  • build_authorization_params        │
             │  • extract_callback_data             │
             │  • exchange_code                     │
             │  • get_user_info / validate_user_info│
             │                                      │
             │  NO HTTP handlers, NO routes         │
             └──────────────────────────────────────┘
```

`OAuth2Provider` is a pure upstream-identity strategy. HTTP shape lives on
`AuthCompletion` subclasses; dispatch lives on `AuthRouter`.

## Completions shipped

Two transports, two classes:

| Class               | kind      | entry                                             | extra routes                                              | final artifact                          |
| ------------------- | --------- | ------------------------------------------------- | --------------------------------------------------------- | --------------------------------------- |
| `SessionCompletion` | `session` | `GET /{provider}/login?next=`                     | —                                                         | browser session cookie                  |
| `TokenCompletion`   | `token`   | `GET /{provider}/authorize` (OAuth 2.0 auth-code) | `POST /{provider}/link`, `POST /{provider}/finalize-link` | local auth code → JWT via `POST /token` |

Each class internally handles two sub-flows, dispatching on fields in
`completion_state`:

### `SessionCompletion`

Branches on whether there's an authenticated user at `start()`:

- **Not authenticated** → resolve/create user via `exchange_and_resolve_user`,
  make session cookie, redirect to `next`.
- **Already authenticated** → attach provider account to current user via
  `exchange_and_attach_social_account`. Session unchanged. Redirect to `next`.

Completion state carries `{"next_url", "user_id"?}` — presence of `user_id`
marks the attach path.

### `TokenCompletion`

Branches on which endpoint was hit at start:

- **`GET /authorize`** → standard OAuth 2.0 auth-code. Stores
  `sub_flow="auth_code"`. On callback: exchange, resolve user, issue local auth
  code, redirect to client `redirect_uri`.
- **`POST /link`** → authenticated JSON endpoint. Stores `sub_flow="link"` +
  `user_id`. Returns authorization URL in JSON for SPA to redirect to. On
  callback: defer exchange, issue link code, redirect with `?link_code=`. SPA
  then calls `POST /finalize-link` with its PKCE verifier to complete.

## State

`AuthFlowState` persists between entry and callback at
`oauth:authorization_request:{state}`:

```python
class AuthFlowState(BaseModel):
    kind: str  # "session" | "token"
    provider_id: str
    state: str  # anti-CSRF token sent to provider
    provider_code_verifier: str | None  # PKCE verifier for provider leg
    completion_state: dict[str, Any]  # mode-specific, opaque to router
```

## Shared helpers (`_provider_service.py`)

- `prepare_authorization(provider, request, context, *, kind, completion_state)`
  — generate state + PKCE, persist `AuthFlowState`, build provider query params.
- `parse_callback_and_load_state(provider, request, context)` — extract callback
  data, load persisted state, raise `OAuth2Exception` on missing/invalid.
- `exchange_and_resolve_user(provider, context, ...)` — exchange provider code,
  fetch/validate user info, find or create local user + `SocialAccount`. Used by
  session-login and auth-code sub-flows.
- `exchange_and_attach_social_account(user, provider, context, ...)` — same
  pipeline but attaches to a _known_ user. Used by session-attach and
  link-finalize sub-flows.

## Router dispatch

```python
# /{provider}/{kind} — one per completion
async def entry_handler(request, context):
    return await completion.start(request, context, provider)


# /{provider}/callback — one per provider; dispatches by state.kind
async def callback_handler(request, context):
    try:
        callback_data, flow_state = await parse_callback_and_load_state(
            provider, request, context
        )
    except OAuth2Exception as e:
        return Response.error(e.error, error_description=e.error_description)

    completion = completion_map[flow_state.kind]
    if not callback_data.code:
        return await completion.on_failure(
            request,
            context,
            OAuth2Exception("server_error", "No authorization code received"),
            flow_state,
        )
    try:
        return await completion.complete(
            request,
            context,
            provider,
            callback_data.code,
            callback_data.extra,
            flow_state,
        )
    except OAuth2Exception as e:
        return await completion.on_failure(request, context, e, flow_state)
```

## Consumer API

```python
from cross_auth.completions import SessionCompletion, TokenCompletion
from cross_auth.fastapi import CrossAuth

auth = CrossAuth(
    providers=[github],
    completions=[
        SessionCompletion(
            session_config=SESSION_CONFIG,
            login_url="/",
            default_post_login_redirect_url="/profile",
        ),
        TokenCompletion(),
    ],
    storage=secondary_storage,
    accounts_storage=accounts_storage,
    create_token=create_token,
    trusted_origins=[...],
    session_config=SESSION_CONFIG,
    config={"account_linking": {"enabled": True}, "allowed_client_ids": [...]},
)
```

Two classes. Consumer picks transports. Internal sub-flow branching
(login/attach for session, auth-code/link for token) is invisible.

## Full route table (per provider)

```text
GET       /auth/{provider}/login           SessionCompletion    session, login-or-attach
GET       /auth/{provider}/authorize       TokenCompletion      auth-code entry
POST      /auth/{provider}/link            TokenCompletion      SPA link entry
POST      /auth/{provider}/finalize-link   TokenCompletion      SPA link completion
GET|POST  /auth/{provider}/callback        unified dispatch by state.kind
POST      /auth/token                      Issuer               code → JWT / password → JWT
```

Register GitHub (or any provider) once with callback
`https://app/auth/github/callback`.

## Why this shape

- **One callback URL per provider.** GitHub/Google/etc. only need to register
  one redirect URI.
- **Mode is expressed by the entry endpoint**, not by a flag. Intent is baked
  into the URL a client chooses.
- **Sub-flow dispatch is internal.** Consumer sees two classes ("session" and
  "token"), not four.
- **Framework concerns live on the completion**, not the provider.
  `SessionCompletion` knows about cookies; `OAuth2Provider` doesn't.
- **New transports slot in without schema changes.** Adding a magic-link or
  passkey mode means adding one more `AuthCompletion` subclass — no router or
  provider changes.
