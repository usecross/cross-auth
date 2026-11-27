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
session's `status` is `active`, `expired` or `revoked`. `last_active_at` is when
the session was last used, to within five minutes by default (see
[Last Activity](#last-activity)).

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
`user`, or `None` when the token is unknown, revoked or expired, when the
accounts storage no longer returns the user, or when
[`user_can_authenticate`](#refuse-suspended-or-deleted-users) refuses the user.
Sliding sessions are refreshed as they are for requests.

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

The session lookup, any sliding-session refresh and the
[activity](#last-activity) recording run first, in the session storage's own
sessions, so they never commit while Cross-Auth has a transaction open in `db`.
Cross-Auth never commits or closes `db`. The accounts storage needs a
`with_read_session(session)` method, which returns a copy of the storage whose
user lookups run in `session`. The SQLModel accounts storage has one; with other
accounts storages, `db_session` raises `TypeError`.

With `user_can_authenticate`, the user must be checked before the refresh, so
Cross-Auth checks a copy that the accounts storage loads in its own session,
then refreshes the session, and only then loads the user you get back in `db`.
That costs one more user lookup per call. Without it, the user is loaded only
after the refresh and the activity recording, so a session whose user was
deleted still records that use before the call returns `None`. Revoke or delete
a user's sessions when you delete the user.

### Refuse Suspended or Deleted Users

Pass `user_can_authenticate` to refuse a user at every point Cross-Auth lets
them in: each login, and each use of a session. It takes the user and returns
whether they may sign in, or the error that tells them why not:

```python
def user_can_authenticate(user: User) -> bool:
    return user.deleted_at is None and user.suspended_at is None


auth = CrossAuth(
    providers=[],
    storage=secondary_storage,
    accounts_storage=accounts_storage,
    session_storage=session_storage,
    user_can_authenticate=user_can_authenticate,
)
```

When it returns `False`, logins are refused with `403 access_denied` ("Sign-in
is not allowed") before the `login` hooks run and before anything is issued.
That covers `auth.login()`, `auth.issue_session_token()`,
`auth.sign_in_with_id_token()`, browser sign-in and `/token`, including a custom
`token_issuer`. A user ID the accounts storage does not find is refused the same
way. A session of a refused user counts as no session:

- `get_current_user` returns `None`, `require_current_user` answers 401 and
  `authenticate_session_token` returns `None`.
- `GET /sessions`, `DELETE /sessions/{session_id}` and
  `POST /sessions/revoke-others` answer `401 unauthorized`, like the other
  routes that need a signed-in user.
- `POST /logout` still works: it only ends the caller's own session.

Cross-Auth asks only once it has verified who the user is. `auth.authenticate()`
raises the refusal only after the password matches; a wrong password still
returns `None`, so nobody learns whether an account may sign in without its
password. In the same way, `auth.resolve_id_token_user()` checks once the token
is verified, and browser sign-in once the provider has confirmed the identity.

To tell the user why, return a `CrossAuthException` instead of `False`. A login
raises it in place of `access_denied`, and a use of a session counts it as
`False`:

```python
from cross_auth.exceptions import CrossAuthException


def user_can_authenticate(user: User) -> bool | CrossAuthException:
    if user.deleted_at is not None:
        return CrossAuthException(
            "account_deleted",
            "This account was deleted. Contact support to restore it.",
            status_code=403,
        )
    if user.suspended_at is not None:
        return CrossAuthException(
            "account_suspended",
            "This account is suspended. Contact support.",
            status_code=403,
        )
    return True
```

Each login answers with it as it answers its other errors:

- Browser sign-in, and connecting or linking a provider with `allow_login`,
  answer with its `error`, `error_description` and `status_code`.
- Browser sign-in for an OAuth client redirects to the client's `redirect_uri`
  with its `error` and `error_description`, as OAuth errors do.
- `/token` answers it as a 400 OAuth error, as it does for hook errors.
- `auth.authenticate()`, `auth.login()`, `auth.issue_session_token()`,
  `auth.sign_in_with_id_token()` and `auth.resolve_id_token_user()` raise it.

On a use of a session nothing is raised: `get_current_user` returns `None`, the
session routes answer `401 unauthorized`, and so on, as for `False`. A user
whose account was suspended while signed in finds themselves signed out, and
their next sign-in tells them why.

You can also raise the `CrossAuthException`. Then it propagates from every
check, also on each use of a session, so `get_current_user` and
`require_current_user` used as dependencies raise it too. Return it unless you
want that.

`user_can_authenticate` must return `True`, `False` or a `CrossAuthException`.
Any other exception it returns, such as FastAPI's `HTTPException`, raises
`TypeError` rather than letting the user in.

Register an exception handler for the errors your own calls raise:

```python
from fastapi import Request
from fastapi.responses import JSONResponse


@app.exception_handler(CrossAuthException)
def cross_auth_error(request: Request, exc: CrossAuthException) -> JSONResponse:
    return JSONResponse(
        {"error": exc.error, "error_description": exc.error_description},
        status_code=exc.status_code,
    )
```

Refusing a user does not revoke their sessions, so lifting a suspension lets the
user's sessions work again. To sign a user out for good, revoke their sessions
too:

```python
user.suspended_at = datetime.now(tz=timezone.utc)
db.commit()
auth.revoke_all_sessions(user_id=user.id)
```

`user_can_authenticate` is the safety net behind that: it covers code that
forgets to revoke, a login that races the revocation, and changes made directly
in the database.

Cross-Auth calls it with the user it loaded, on every authenticated request, so
keep it to a quick check of the user's own fields. On each use it runs before
the [sliding refresh](#sliding-sessions), so a refused request does not extend
the session or move its `last_active_at`.

A custom `get_user_from_request` decides itself which users it returns.
`authenticate_session_token` applies `user_can_authenticate`, so a resolver that
uses it for session tokens is covered; check users of other credentials, such as
API keys, yourself.

Without `user_can_authenticate`, every user may sign in, and logins do not load
the user to ask.

#### Soft-Deleted Users

Keep soft-deleted users where the accounts storage finds them, and refuse them
in `user_can_authenticate`. Hiding them from the storage, for example with a
SQLModel [`filter_user_query`](/docs/storage#adapter-customization), breaks
sign-in. Their provider identity still points at them, so signing in with it
answers `server_error`, and their email looks unused, so signing up with it
creates a second user with the same email.

A user the storage finds is refused with your error wherever they sign in: with
their password, their provider identity, an ID token, or a new provider identity
for their email that auto-linking would link to them. That identity is not
attached. A new identity that cannot be linked automatically gets
`account_not_linked` without `user_can_authenticate` being asked, since it has
not shown that it owns the account. And the user's sessions count as no session.

A soft-deleted user keeps their email, so nobody can sign up with it again. If
your application allows that, change the deleted user's email when you delete
them.

### Change a Password

`auth.change_password()` changes the password of the user the request's session
signs in, and signs their other devices out. A user who changes their password
because someone else knows it locks that person out, even of a session they
already hold:

```python
from pydantic import BaseModel


class PasswordChange(BaseModel):
    current_password: str | None
    new_password: str


@app.post("/change-password")
def change_password(request: Request, body: PasswordChange):
    auth.change_password(
        request,
        current_password=body.current_password,
        new_password=body.new_password,
    )
    return {"ok": True}
```

It finds the user as `require_current_user` does, from the session cookie or
`Authorization: Bearer ...`, and answers a request without a session, or with
one `user_can_authenticate` refuses, with `401 unauthorized`. Then:

1. `current_password` must match the user's password; a wrong or missing one
   raises `400 invalid_password` and changes nothing. It is `None` only for a
   user without a password, such as one who signed up with a provider and sets a
   first password.
2. The accounts storage hashes `new_password` with the
   [password hasher](#password-hashing) and stores it, in its
   [`set_password` method](/docs/storage#accountsstorage); an accounts storage
   without one raises `TypeError`. The default bcrypt hasher refuses a password
   longer than bcrypt's 72 bytes with `400 password_too_long`. Check your own
   rules, such as a minimum length, before you call `change_password`.
3. The user's other sessions are revoked through the
   [`session.revoke` hooks](/docs/hooks#sessionrevoke), with `scope="others"`.
   The session that made the change stays signed in, and its token does not
   change. Pass `revoke_other_sessions=False` to keep the other sessions too.

It returns the updated user. The password is stored before the sessions are
revoked, so a `session.revoke` before hook that refuses raises once the password
has changed. The revocation needs the new password committed first: until then,
a login with the old one could start a session it misses. So with an accounts
storage that joins your application transaction, `change_password` raises
`RuntimeError` before changing anything, unless you pass
`revoke_other_sessions=False`. The SQLModel storage commits each write before it
returns.

`change_password` raises `CrossAuthException` for these errors, so register an
exception handler, as for
[`user_can_authenticate`](#refuse-suspended-or-deleted-users), and rate-limit
the route like a login: it checks a password. See
[Security Integration](/docs/security#change-passwords).

A password changed any other way, such as from a password reset link, an admin
page or a script, signs no one out. Revoke the user's sessions yourself when it
should:

```python
auth.revoke_all_sessions(user_id=user.id)
```

### Password Hashing

`auth.authenticate()`, `auth.change_password()` and the OAuth password grant
verify passwords with one password hasher, and `change_password()` hashes the
new password with it too. The default hashes with bcrypt. Pass `password_hasher`
to use another:

```python
from pwdlib import PasswordHash

auth = CrossAuth(
    providers=[],
    storage=secondary_storage,
    accounts_storage=accounts_storage,
    session_storage=session_storage,
    password_hasher=PasswordHash.recommended(),
)
```

A hasher is any object with the two methods of the `cross_auth.PasswordHasher`
protocol. Cross-Auth passes their arguments by position, so the parameters can
have any name:

```python
class PasswordHasher(Protocol):
    def hash(self, password: str, /) -> str: ...

    def verify(self, password: str, hash: str, /) -> bool: ...
```

pwdlib's `PasswordHash` and passlib's `CryptContext` have both methods, so they
work as they are. List more than one scheme to move users to a new one: new
hashes use the first, and the hashes your users already have keep verifying.

```python
from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher
from pwdlib.hashers.bcrypt import BcryptHasher

password_hasher = PasswordHash((Argon2Hasher(), BcryptHasher()))
```

Users move to the first scheme as they sign in. Both libraries also have
`verify_and_update`, the method the `cross_auth.RehashingPasswordHasher`
protocol adds. With such a hasher and an accounts storage that can replace a
hash, as the SQLModel adapter can, `authenticate()` and the OAuth password grant
store a new hash for a matching password whose hash is outdated: from another
scheme, or made with older settings. The storage replaces it only if it still
holds the hash that was checked, so a password changed in the meantime keeps its
own. When the replacement fails, the old hash stays and the user still signs in.
Because sign-ins write hashes in the new scheme, follow the two deploys below
when several instances serve your app.

When several instances serve your app, switch in two deploys. First deploy,
everywhere, a hasher that verifies both schemes but still hashes with the old
one, `PasswordHash((BcryptHasher(), Argon2Hasher()))`. Once no instance runs the
old hasher, deploy the new scheme first. Otherwise an instance still on the old
hasher can't read the hashes the new one writes, and those users fail to sign in
there until it's replaced.

```python
from passlib.context import CryptContext

password_hasher = CryptContext(schemes=["argon2", "bcrypt"])
```

passlib has no type hints, so type checkers don't check a `CryptContext` against
the protocol. argon2-cffi's own `PasswordHasher` doesn't fit: its `verify` takes
the hash first and raises for a wrong password. Use argon2 through pwdlib or
passlib.

Hash the passwords you store yourself, such as at signup, with the same hasher,
so that `authenticate()` can verify them:

```python
hashed_password = auth.password_hasher.hash(password)
```

**Hashes the hasher can't read.** A stored hash the hasher doesn't recognize,
such as one another library made, never matches: whatever `verify` raises counts
as a wrong password. `authenticate()` returns `None`, `change_password()` raises
`400 invalid_password`, and the password grant answers `invalid_grant`.
Cross-Auth logs it on the `cross_auth._password` logger with the error's type,
never the hash: a warning the first time each hasher raises each type of error,
then at debug level, so repeated sign-ins can't flood the log. A user whose hash
can't be read can't sign in with a password, so list every scheme your users'
hashes use.

**Timing.** Each check costs one verification. An unknown email, a user without
a password and a hash the hasher can't read each verify a dummy hash, which the
hasher makes the first time it checks a password, from a random 64-character
ASCII password. `hash` must accept that password: while it refuses it, every
check raises `RuntimeError`.

The dummy evens out the time of checks against hashes of the hasher's current
scheme and cost, the ones it writes. It doesn't make checks take the same time
across schemes or costs. While users move to a new scheme, or after you raise
the cost, accounts that still have an older hash verify in that hash's time, so
an attacker can tell them from unknown emails until they're rehashed, which
happens as they sign in when the hasher and the accounts storage can upgrade
hashes.

For the dummy to keep the cost at one verification, `verify` returns `False`
only for a wrong password. For a hash it can't read, it raises, and before doing
a verification's work, as bcrypt, pwdlib and passlib do. A hasher that returns
`False` for such a hash answers faster for those users, and one that raises
after the work answers slower.

**The default** is `BcryptPasswordHasher`, with bcrypt's default cost. bcrypt
reads only the first 72 bytes of a password. It refuses to hash a longer one,
raising `CrossAuthException("password_too_long")`, rather than cut it short. It
verifies the first 72 bytes, so users whose hash another library made from a
longer password, as passlib did, keep signing in. pwdlib's and passlib's bcrypt
refuse to verify a password that long with bcrypt 5, which counts as a wrong
password.

When the hasher's settings or schemes change, an older hash is replaced the next
time the user signs in, if the hasher has `verify_and_update` and the accounts
storage can replace hashes. Otherwise it stays until the user changes their
password.

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

A sliding refresh succeeds only while the stored session is still active.
`get_current_user` and `authenticate_session_token` load the session's user
before they refresh, and with
[`user_can_authenticate`](#refuse-suspended-or-deleted-users) every session read
through `CrossAuth` checks the user first, so a session whose user is missing or
refused is not extended. If revocation wins the race between lookup and refresh,
Cross-Auth rejects that session and does not extend its cookie. Expiry is also
checked at the refresh attempt, so time spent in the initial lookup cannot
revive an expired session.

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

### Last Activity

A session's `last_active_at` records when it was last used, apart from its
expiry. A request that uses the session, by cookie or bearer token, sets it to
the current time once it is at least `activity_interval` seconds old: five
minutes by default. A sessions list can then show "active 3 minutes ago" without
a database write on every request. A sliding refresh sets it in the same write.
Recording activity never moves `expires_at` or re-sends the cookie.

```python
CrossAuth(..., config={"session": {"activity_interval": 60}})
```

`activity_interval` is an int from `0`, which records every request, to a year.
Set it to `None` to update `last_active_at` only at sign-in and on a sliding
refresh.

A session in use costs at most one write per interval, and an idle session none.
Activity is recorded where a sliding refresh would be, after the same user
checks, and never by logout. With a custom `get_user_from_request`, the session
is read and its activity recorded before your resolver runs, as for a sliding
refresh. Recording is best-effort: when the database refuses the update, the
SQLModel storage logs a warning on the `cross_auth.storage.sqlmodel` logger and
the request keeps its session. A custom session storage needs a
[`record_activity` method](/docs/storage#sessionstorage) to record activity at
all, and handles its own database errors the same way; without one,
`last_active_at` moves only at sign-in and on a sliding refresh.

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

It verifies with bcrypt by default; pass `password_hasher=` to verify with the
[password hasher](#password-hashing) you give `CrossAuth`. It always runs one
verification, even for an email with no account, so response times don't tell
which emails have accounts, as long as stored hashes use the hasher's current
scheme and cost. See [Password Hashing](#password-hashing) for when they don't.

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
