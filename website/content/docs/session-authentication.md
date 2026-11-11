---
title: Session Authentication
description: Manage user sessions with secure cookies.
order: 2
section: Guides
---

## Overview

Session-based authentication is the traditional approach for server-rendered web
applications. After a user logs in with their email and password, the server
creates a session and sends an opaque session-token cookie to the browser.
Subsequent requests include this cookie, allowing the server to identify the
user.

Cross-Auth provides a high-level `CrossAuth` class with `login()` and `logout()`
methods for framework integrations, as well as lower-level functions for custom
session management.

## Using the CrossAuth Class (Recommended)

The FastAPI `CrossAuth` class bundles session creation, cookie management, and
cleanup into simple methods:

### Authenticate and Login

```python
from cross_auth.fastapi import CrossAuth
from fastapi.responses import JSONResponse

auth = CrossAuth(
    providers=[],
    storage=secondary_storage,
    accounts_storage=accounts_storage,
    session_storage=session_storage,
)

# Verify credentials
user = auth.authenticate(email, password)
if user is None:
    # Invalid credentials
    ...

# Create session + set cookie in one step
response = JSONResponse({"user": user.id})
auth.login(str(user.id), response=response)
```

### Logout

`auth.router` mounts `POST /logout` whenever `session_storage` is configured.
Include the router under a prefix and clients call it there:

```python
app.include_router(auth.router, prefix="/api/v1")
# POST /api/v1/logout
```

The route revokes the caller's session and answers `204 No Content` with a
cleared session cookie. It reads the session token from the session cookie, then
from `Authorization: Bearer ...`, so it logs out browser sessions and tokens
from `/token` or `auth.issue_session_token()` alike. It answers 204 also when
the request has no token, or one that is unknown, expired, or already revoked:
logging out never fails with 401, so a client that answers 401 by signing out
again cannot loop.

To log out everywhere, send `{"scope": "all"}` as the JSON body. The route then
revokes every session of the caller's user (browser cookies and bearer tokens on
every device), still answering 204. Without a valid session there is no user to
log out, and nothing is revoked. An unknown `scope` answers
`400 invalid_request`. To revoke a user's other sessions while keeping the
current one, use [`POST /sessions/revoke-others`](#list-and-revoke-sessions).

To log out from your own route, call `logout()`; the route runs the same code:

```python
from fastapi import Request

# Revoke session + clear cookie in one step
response = JSONResponse({"ok": True})
auth.logout(request, response=response)

# Or revoke every session of the user
auth.logout(request, response=response, scope="all")
```

### List and Revoke Sessions

With `session_storage` configured, `auth.router` also mounts JSON routes that
let users see where they are signed in and sign other devices out. Paths are
relative to where you include the router:

| Route                           | Response                    | Operation ID            |
| ------------------------------- | --------------------------- | ----------------------- |
| `GET /sessions`                 | `200` with a `SessionList`  | `list_sessions`         |
| `DELETE /sessions/{session_id}` | `204 No Content`            | `revoke_session`        |
| `POST /sessions/revoke-others`  | `200` with `{"revoked": n}` | `revoke_other_sessions` |

Like `/logout`, these routes act on the session that authenticates the request
(the session cookie, then `Authorization: Bearer ...`) and on that session's
user. A request without a valid session answers `401 unauthorized`.

`GET /sessions` lists the caller's sessions, newest first. It never returns
session tokens or their hashes:

```json
{
  "sessions": [
    {
      "id": "8b0c…",
      "status": "active",
      "client_id": null,
      "client_name": null,
      "user_agent": "Mozilla/5.0 …",
      "ip": "203.0.113.7",
      "login_method": "github",
      "created_at": "2026-11-04T09:12:44Z",
      "last_active_at": "2026-11-04T17:40:02Z",
      "expires_at": "2026-11-05T09:12:44Z",
      "revoked_at": null,
      "current": true
    }
  ],
  "next_cursor": null
}
```

By default it lists active sessions only. Pass `status=expired`,
`status=revoked` or `status=all` to show a history instead, for example a list
that also shows signed-out devices with when they expired or were revoked. Each
session's `status` is `active`, `expired` or `revoked`. `last_active_at` is the
sign-in time, then the latest sliding refresh, so with `update_age` it is
accurate to within that interval.

`current` marks the session that authenticated the request. Pages hold 50
sessions; pass `limit` (1 to 100) to change that, and send a page's
`next_cursor` back as `cursor` to get the next one, with the same `status`. An
invalid `status`, `limit` or `cursor` answers `400 invalid_request`.

`DELETE /sessions/{session_id}` revokes one of the caller's sessions, including
the current one. Revoking the current cookie session also clears the cookie, as
`/logout` does. An id that does not exist and another user's session both answer
the same `404 session_not_found`, so nobody can probe for sessions. Revoking a
session that is already revoked or expired answers 204 and leaves it as it was,
so an expired session keeps its `expired` status.

`POST /sessions/revoke-others` revokes every active session of the caller except
the current one, and `revoked` says how many. Expired sessions stay expired and
are not counted.

Both run the [`session.revoke` hooks](/docs/hooks#sessionrevoke), so a before
hook can refuse a revocation and an after hook can audit it. `DELETE` and `POST`
change state, so protect them from CSRF when the session cookie can authenticate
them, like `/logout`: see [Security Integration](/docs/security). To build your
own pages instead, use `auth.list_sessions()`, `auth.get_session()`,
`auth.revoke_session()`, `auth.revoke_other_sessions()` and
`auth.revoke_all_sessions()`; the revoke methods run the same hooks.

### Get Current User

`get_current_user` and `require_current_user` take only the request, so they
work as FastAPI dependencies and as plain calls — in shared-context builders,
GraphQL resolvers, or template helpers — with a single API:

```python
from typing import Annotated

from fastapi import Depends


@app.get("/me")
def me(user: Annotated[User | None, Depends(auth.get_current_user)]): ...


@app.get("/protected")
def protected(
    user: Annotated[User, Depends(auth.require_current_user)],
): ...  # raises 401 if not logged in


def build_context(request: Request) -> dict:  # outside dependency injection
    return {"user": auth.get_current_user(request)}
```

### Authenticate a Session Token

`authenticate_session_token(token)` looks a session token up without a request.
It returns an `AuthenticatedSession` with the active `session` record and its
`user`, or `None` when the token is unknown, revoked or expired, or when the
accounts storage no longer returns the user. Sliding sessions are refreshed as
they are for requests.

It never calls `get_user_from_request`, so a resolver that also accepts other
credentials can use it for session tokens:

```python
def get_user_from_request(request: HTTPRequest) -> User | None:
    token = get_bearer_token(request)
    if token is None:
        return None
    if auth.identify_token(token) == "session":
        result = auth.authenticate_session_token(token)
        return result.user if result else None
    return find_user_by_api_key(token)
```

The SQLModel storages read in database sessions they open and close themselves,
so the user comes back detached: its columns are readable, but a relationship
that loads lazily raises `DetachedInstanceError`. Pass your own database session
as `db_session` and the user is loaded in it instead, so it belongs to that
session:

```python
bearer = HTTPBearer()


def current_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(bearer)],
    db: Annotated[Session, Depends(get_db)],
) -> User:
    result = auth.authenticate_session_token(credentials.credentials, db_session=db)
    if result is None:
        raise HTTPException(status_code=401)
    return result.user  # relationships load, and you can change and commit it
```

The session lookup and any sliding-session refresh run first, in the session
storage's own sessions, so the refresh never commits while Cross-Auth has a
transaction open in `db`. Cross-Auth never commits or closes `db`. The accounts
storage needs a `with_read_session(session)` method, which returns a copy of the
storage whose user lookups run in `session`. The SQLModel accounts storage has
one; with other accounts storages, `db_session` raises `TypeError`.

### Sliding Sessions

With `update_age` configured, reads refresh the stored session record — and the
browser's cookie must be re-sent so its `Max-Age` slides too. Install
`SessionCookieMiddleware` once and rolled cookies are delivered on whatever
response the handler produces, including responses returned directly (redirects,
streaming, server-rendered pages):

```python
from cross_auth.fastapi import SessionCookieMiddleware

app.add_middleware(SessionCookieMiddleware)
```

A sliding refresh succeeds only while the stored session is still active. If
revocation wins the race between lookup and refresh, Cross-Auth rejects that
session and does not extend its cookie. Expiry is also checked at the refresh
attempt, so time spent in the initial lookup cannot revive an expired session.

Revocation does not cancel a request that has already authenticated. If refresh
finishes first, a later revocation still invalidates the stored session for
subsequent authentication.

Without `update_age` the middleware is inert and can be omitted. If a session
refreshes and the middleware is missing, Cross-Auth emits a warning instead of
silently letting the browser cookie lapse. A cookie the handler already set
itself — `logout()` clearing it, `login()` replacing it — always wins over the
rolled copy.

`session_storage` is optional when constructing `CrossAuth`, but session-backed
features require it. `login()`, `logout()`, and session-management methods raise
clearly when no `session_storage` is configured. With an `OAuthServer`, the
built-in `/token` endpoint is registered, but successful token issuance requires
`session_storage` or the server's `token_issuer`.

### Token Prefix

Set `token_prefix` to give the session tokens Cross-Auth issues a recognizable
shape, like GitHub's `ghp_` tokens:

```python
auth = CrossAuth(
    providers=[],
    storage=secondary_storage,
    accounts_storage=accounts_storage,
    session_storage=session_storage,
    config={"session": {"token_prefix": "myapp"}},
)
```

New tokens are then `myapp_` followed by 32 random base62 characters and a
6-character checksum, for cookie logins, `/token`, `issue_session_token()` and
`sign_in_with_id_token()` alike. A token that leaks into a log or a repository
is easy to spot, secret scanners can match it (`myapp_[0-9A-Za-z]{38}`), and the
checksum lets you reject a mistyped or made-up token without a storage lookup.
The prefix is 1 to 16 lowercase letters and digits, starting with a letter;
anything else raises `ValueError` when `CrossAuth` is created.

`auth.identify_token(token)` returns `"session"` for a token with that prefix
and a valid checksum, and `None` otherwise:

```python
if auth.identify_token(token) == "session":
    user = auth.get_current_user(request)
```

It reads the token's shape only and does not authenticate it: a well-formed
token can still be unknown, expired or revoked, so authenticate the request with
`get_current_user` as usual. Sessions issued before you set the prefix keep
working until they expire, because lookups accept any token, but
`identify_token` does not recognize them; don't use it to reject tokens while
those sessions are still live.

## Lower-Level Session Functions

For custom frameworks or advanced use cases, Cross-Auth also exposes plain
functions for session management.

### Authenticating Users

The `authenticate` function verifies an email/password combination against your
user storage:

```python
from cross_auth._password import authenticate

user = authenticate(email, password, accounts_storage)

if user is None:
    # Invalid credentials
    ...
```

This function uses **constant-time verification** -- it always runs bcrypt even
for non-existent users, preventing timing attacks that could enumerate valid
email addresses.

Cross-Auth verifies passwords; your application hashes them when a user sets
one. Store a bcrypt hash (the `$2b$` format produced by the `bcrypt` package or
by passlib) in `hashed_password`. bcrypt uses only the first 72 bytes of a
password, so any password that shares those bytes verifies against the hash.
Decide how to handle longer passwords when hashing: reject them, as
`bcrypt.hashpw` does from bcrypt 5, or hash them with SHA-256 first and bcrypt
the digest. Verification compares the first 72 bytes either way, so users whose
hash was made from a longer password keep signing in.

### Creating Sessions

After authentication, create a session to persist the login:

```python
from cross_auth._session import create_session

session_token, session_record = create_session(str(user.id), session_storage)
```

The session token is a cryptographically secure random value
(`secrets.token_urlsafe(32)`, ~256 bits of entropy). Pass `token_prefix="myapp"`
for the [prefixed format](#token-prefix) instead, ~190 bits of entropy.
Cross-Auth stores only a hash of that token in `SessionStorage`, together with
the session metadata and expiry.

Cross-Auth's own logins, such as `/token` and browser logins, fill `user_agent`
and `ip` from the request. The IP is the client address the framework reports
(`request.client.host` in FastAPI), never a forwarding header: behind a proxy,
run your server so it trusts your proxies' forwarded headers, such as
`uvicorn --proxy-headers --forwarded-allow-ips=<your proxies>`, or every session
shows the proxy's address. To store no IP at all, set `store_ip` to `False`:

```python
CrossAuth(..., config={"session": {"store_ip": False}})
```

New sessions then store no IP, even one you pass in `metadata` or a `login` hook
sets. Sessions created before keep theirs until they end; to remove those
sooner, clear the `ip` of your stored sessions.

Clients choose most of that metadata, and the session list shows it back to
users, so Cross-Auth cleans it before storing it, including values a `login`
hook sets:

- In `client_id`, `client_name` and `user_agent`, control and other unprintable
  characters become spaces and runs of whitespace become one space. `user_agent`
  is cut to 512 characters, the other two to 255.
- `ip` must be a single IP address. IPv6 zone IDs are dropped and IPv4-mapped
  IPv6 addresses become IPv4. Anything else, such as a whole `X-Forwarded-For`
  list, is stored as `None`.
- Values left empty are stored as `None`.

#### Session Fixation Protection

Always create a **new** session after authentication. Never reuse an existing
session token from before login -- this prevents session fixation attacks.

### Reading Sessions

Retrieve a session by its token:

```python
from cross_auth._session import get_session

session = get_session(session_token, session_storage)

if session is None:
    # Session not found or expired
    ...

print(session.user_id)
print(session.created_at)
print(session.status)
```

### Deleting Sessions

Revoke a session to log the user out:

```python
from cross_auth._session import delete_session

delete_session(session_token, session_storage)
```

This revokes the stored session record. It is a no-op if the session doesn't
exist.

### Bearer Tokens

For an application-owned token verifier, use `get_bearer_token(request)` to
extract the credential from a Cross-Web `HTTPRequest`:

```python
from cross_auth import get_bearer_token

token = get_bearer_token(request)
```

The helper accepts case-insensitive header names and the Bearer scheme, and
returns `None` for a missing or empty bearer credential. It only extracts the
token: your verifier must still validate it and check the user's eligibility.

The built-in OAuth `/token` endpoint issues the same kind of opaque session
token that `create_session()` returns. API clients send it with
`Authorization: Bearer ...`, and Cross-Auth resolves it through
`SessionStorage`.

For clients that authenticate outside `/token` and outside a browser — a GraphQL
sign-in mutation for a native app, a CLI — mint the token directly:

```python
token, record = auth.issue_session_token(
    str(user.id),
    max_age=60 * 60 * 24 * 30,  # e.g. longer-lived mobile sessions
    metadata={"client_name": "ios"},
)
```

The client sends it as `Authorization: Bearer ...` and `get_current_user`
resolves it like any other session. No cookie is set; the `login` hooks run
around the creation with `credential="bearer"`, so the same policy and audit
handlers cover cookie logins, `/token` grants, and this path.

Because bearer tokens are session records, they are revocable with the same
session-management APIs. Cross-Auth does not issue JWT access tokens by default.

### Login method

A session's `login_method` records how the user signed in: `"password"`, or a
social provider's id such as `"github"` or `"google"`. Use it to show "Signed in
with GitHub" next to each session in a session list.

Cross-Auth sets it on the sessions it creates:

| Sign-in                                     | `login_method`                  |
| ------------------------------------------- | ------------------------------- |
| Browser sign-in through `/{provider}/login` | The provider id                 |
| `/token` authorization code grant           | The provider the code came from |
| `/token` password grant (deprecated)        | `"password"`                    |
| `auth.sign_in_with_id_token(provider, ...)` | `provider`                      |

For sessions your code creates, pass `login_method`. The value is free-form, so
you can also use your own, such as `"passkey"`:

```python
user = auth.authenticate(email, password)
if user is None:
    raise HTTPException(status_code=401, detail="Invalid email or password")
auth.login(str(user.id), response=response, login_method="password")

token, record = auth.issue_session_token(str(user.id), login_method="passkey")
```

For a native app that sends a provider `id_token`, `sign_in_with_id_token` signs
the user in and issues the bearer session in one call, recording the provider
(see Native Sign-In in [Social Providers](/docs/social-providers)):

```python
token, record, user, created = auth.sign_in_with_id_token(
    "apple", id_token, nonce=nonce, metadata={"client_name": "ios"}
)
# record.login_method == "apple"
```

Read the value back as `record.login_method`; it is `None` for sessions created
before Cross-Auth recorded it. Every `login` hook event carries it as
`event.login_method`, and a `before` hook can replace it (see
[`login`](/docs/hooks#login)).

### Cookie Helpers

Cross-Auth provides helpers to create properly configured session cookies:

#### Setting the Session Cookie

```python
from cross_auth._session import make_session_cookie

cookie = make_session_cookie(session_token)
# cookie.name = "session_id"
# cookie.secure = True
# cookie.httponly = True
# cookie.samesite = "lax"
# cookie.path = "/"
```

#### Clearing the Session Cookie

```python
from cross_auth._session import make_clear_cookie

cookie = make_clear_cookie()
# cookie.value = ""
# cookie.max_age = 0
```

#### Custom Configuration

Pass a `SessionConfig` to override defaults:

```python
from cross_auth import SessionConfig
from cross_auth._session import make_session_cookie

config: SessionConfig = {
    "max_age": 3600,  # 1 hour
    "cookies": {
        "name": "my_app_session",
        "secure": True,
        "httponly": True,
        "samesite": "strict",
        "path": "/",
        "domain": ".example.com",
    },
}

cookie = make_session_cookie(session_token, config)
```

## Cookie Defaults

| Setting            | Default        | Notes                                 |
| ------------------ | -------------- | ------------------------------------- |
| `max_age`          | `86400` (24h)  | Session lifetime in seconds           |
| `store_ip`         | `True`         | Store the client's IP with sessions   |
| `cookies.name`     | `"session_id"` | Name of the cookie                    |
| `cookies.secure`   | `True`         | Only sent over HTTPS                  |
| `cookies.httponly` | `True`         | Not accessible via JavaScript         |
| `cookies.samesite` | `"lax"`        | Limits some cross-site cookie sending |
| `cookies.path`     | `"/"`          | Cookie is valid for all paths         |
| `cookies.domain`   | `None`         | Scoped to the current domain          |

`SameSite=Lax` is a partial mitigation, not general CSRF protection. Protect
cookie-authenticated mutations and browser login endpoints at the HTTP boundary;
see [Security Integration](/docs/security) for working FastAPI patterns.
