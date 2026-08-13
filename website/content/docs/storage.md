---
title: Storage
description:
  Connect Cross-Auth to your database with a built-in adapter or by implementing
  the storage protocols.
order: 1
section: Guides
---

## Overview

Cross-Auth keeps three storage concerns separate:

- `SecondaryStorage` stores short-lived values such as authorization codes, PKCE
  challenges, and link codes.
- `AccountsStorage` looks up and creates users and their social accounts.
- `SessionStorage` stores durable, revocable session records for browser cookies
  and bearer tokens issued by `/token`.

There are two ways to provide them:

1. **Use a built-in adapter.** Cross-Auth ships a Redis adapter and subclassable
   SQLModel adapters that implement the repetitive protocol code for you. You
   keep ownership of your models and migrations. This is the recommended path
   for most apps.
2. **Implement the protocols directly.** The protocols are plain
   [structural](https://docs.python.org/3/library/typing.html#typing.Protocol)
   interfaces — implement the methods on any object and Cross-Auth will accept
   it. Use this for ORMs without a built-in adapter, or for custom storage.

## Built-in adapters

The adapters are optional and live behind extras, so the core library never
pulls in Redis or SQLModel:

```bash
uv add 'cross-auth[redis]'      # RedisStorage
uv add 'cross-auth[sqlmodel]'   # SQLModel adapters
uv add 'cross-auth[redis,sqlmodel]'
```

### RedisStorage

`RedisStorage` implements `SecondaryStorage`. For the common case, create it
from a Redis URL and close it during application shutdown:

```python
from cross_auth.storage.redis import RedisStorage

secondary_storage = RedisStorage.from_url("redis://localhost:6379")

# On application shutdown:
secondary_storage.close()
```

`from_url()` owns the synchronous redis-py client and its connection pool;
keyword arguments are passed through to `redis.Redis.from_url()`. If you inject
an existing client with `RedisStorage(client)`, it remains caller-owned and
`RedisStorage.close()` leaves it open. Client injection is useful for custom
pools, Redis Cluster or Sentinel setup, instrumentation, and tests. The
read-only `client` property exposes the underlying redis-py client when an
application needs commands outside the secondary-storage protocol.

It requires a **synchronous** redis-py client with `GETDEL` support (redis-py >=
4.2; the `redis` extra installs >= 5.0) against a **Redis server 6.2 or newer**.
`RedisStorage` raises `TypeError` at construction for a client without `getdel`
and for an async client (e.g. `redis.asyncio.Redis`) — an async client's methods
would silently return an unawaited coroutine instead of doing anything, so it's
rejected up front rather than failing on the first call.

It stores values with optional TTL, normalizes byte and string responses to
`str | None`, and uses Redis `GETDEL` for atomic `pop`. A `ttl` of zero or less
means "already expired": the key is deleted instead of stored.

### SQLModelAccountsStorage

Pass your models to `SQLModelAccountsStorage` — it implements all of
`AccountsStorage`, including a working `create_user`. Map app-specific user
columns with the public typed hooks described below. The adapter also has a
private escape hatch for the rarer case where related rows must share its user
transaction.

First, your user-owned models (you control the table names, columns, and
migrations):

```python
from datetime import datetime

from sqlmodel import Field, Relationship, SQLModel


class SocialAccount(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id")
    provider: str
    provider_user_id: str
    access_token: str | None = None
    refresh_token: str | None = None
    access_token_expires_at: datetime | None = None
    refresh_token_expires_at: datetime | None = None
    scope: str | None = None
    provider_email: str | None = None
    provider_email_verified: bool | None = None
    is_login_method: bool = True

    user: "User" = Relationship(back_populates="social_accounts")


class User(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    email: str = Field(index=True, unique=True)
    email_verified: bool = False
    hashed_password: str | None = None

    social_accounts: list[SocialAccount] = Relationship(back_populates="user")

    @property
    def has_usable_password(self) -> bool:
        return self.hashed_password is not None
```

Then the adapter:

```python
from sqlmodel import Session, create_engine

from cross_auth.storage.sqlmodel import SQLModelAccountsStorage

# The "+psycopg" driver needs a database driver installed (e.g. `pip install psycopg`).
engine = create_engine("postgresql+psycopg://localhost/myapp")

accounts_storage = SQLModelAccountsStorage(
    User, SocialAccount, session_factory=lambda: Session(engine)
)
```

`create_user` runs the whole signup as one adapter-owned transaction, commits,
and returns the user fully loaded (so it stays readable after the session
closes), bypassing `filter_user_query` so a freshly created user is always
returned.

The default user creation validates and applies mapped `extra_fields` from the
`user.create` hook, then assigns `email_verified` through the model attribute.
That supports either a mapped field or a writable property backed by a
differently named column.

Use `@auth.before("user.create")` for signup policy and mapped app fields,
`@auth.after("user.create")` for post-commit work such as telemetry or welcome
emails. Those are public lifecycle hooks and apply regardless of the storage
implementation.

If related rows must commit atomically with the user, subclass the adapter and
override its private `_build_user` escape hatch. Call `super()`, add your rows
to the supplied session, and return the user. Do not commit or perform external
I/O here; `create_user` owns the transaction boundary. Because this is a private
method, it may change between releases.

```python
class AccountsStore(SQLModelAccountsStorage[User, SocialAccount]):
    UserModel = User
    SocialAccountModel = SocialAccount

    def _build_user(self, *, session, **kwargs):
        user = super()._build_user(session=session, **kwargs)
        session.add(Team(owner=user))  # joins the same commit
        return user


accounts_storage = AccountsStore(session_factory=lambda: Session(engine))
```

Register policy, mapped fields, and post-commit behavior on the `CrossAuth`
instance:

```python
from dataclasses import replace

from cross_auth.hooks import AfterUserCreateEvent, BeforeUserCreateEvent


@auth.before("user.create")
def require_invite(event: BeforeUserCreateEvent) -> None:
    if not is_invited(event.email):
        raise CrossAuthException("signup_not_allowed", "Invite only")


@auth.before("user.create")
def store_full_name(event: BeforeUserCreateEvent) -> BeforeUserCreateEvent:
    return replace(
        event,
        extra_fields={**event.extra_fields, "full_name": event.user_info["name"]},
    )


@auth.after("user.create")
def track_signup(event: AfterUserCreateEvent) -> None:
    telemetry.capture("account_created", user_id=event.user.id)
```

Everything else (`find_user_by_email`, `find_social_account`,
`create_social_account`, `update_social_account`, `delete_social_account`, and
the rest) is handled by the base.

Configuration is validated at construction: a missing model declaration, a model
missing an attribute the `User`/`SocialAccount` protocols require, or a
non-callable `session_factory` raises a `TypeError` at startup rather than on
the first login. The token columns the adapter writes by default
(`access_token`, `refresh_token`, their expiries, and `scope`) are checked too,
because SQLModel silently ignores unknown constructor kwargs — without the
check, a missing column would silently drop OAuth tokens. An app that
deliberately does not persist provider credentials can declare those optional
fields explicitly:

```python
class AccountsStore(SQLModelAccountsStorage[User, SocialAccount]):
    excluded_social_account_fields = frozenset(
        {
            "access_token",
            "refresh_token",
            "access_token_expires_at",
            "refresh_token_expires_at",
            "scope",
        }
    )
```

Only those five optional credential fields can be excluded; identity and login
fields remain required. The social-account model must still expose the five
credential attributes as readable properties because Cross-Auth reads them when
preserving credentials during a tokenless sign-in. A storage that never persists
credentials can return `None` from those properties.

#### Adapter customization

Override these methods instead of reimplementing whole protocol methods:

- `filter_user_query(statement)` - refine user lookups, e.g. exclude
  soft-deleted users. (`create_user` deliberately skips this filter.)
- `filter_social_account_query(statement)` - scope social accounts, e.g. by
  tenant. Applied to reads **and** writes, so a scoped store can't be made to
  update or delete rows its lookups would never return. It does **not** apply to
  the eager-loaded `user.social_accounts` relationship on a returned user — that
  collection is always loaded unfiltered; use `list_social_accounts` for a
  filtered read.

For related rows that must share user creation's transaction, the private
`_build_user` escape hatch is described above. Prefer typed hooks for everything
that does not need the SQLModel session.

`excluded_social_account_fields` is the corresponding declarative setting for
omitting optional provider credentials from writes.

```python
class AccountsStore(SQLModelAccountsStorage[User, SocialAccount]):
    UserModel = User
    SocialAccountModel = SocialAccount

    def filter_user_query(self, statement):
        # Assumes your User model adds a deleted_at column.
        return statement.where(User.deleted_at == None)  # noqa: E711
```

Custom social-account columns do not require subclass methods. The
`social_account.create` and `social_account.update` hooks can add
`extra_fields`, which the SQLModel adapter validates and writes:

```python
from dataclasses import replace

from cross_auth.hooks import (
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
```

`extra_fields` cannot replace standard social-account fields; use the dedicated
event field when it is writable. Unknown SQLModel column names fail at write
time instead of being silently ignored.

### SQLModelSessionStorage

Pass your session model to `SQLModelSessionStorage` — it implements every
`SessionStorage` method, including keyset cursor pagination and status
filtering. No subclass is needed unless you want to override behaviour.

Your session model must expose the attribute names the `SessionRecord` protocol
reads, plus an internal `token_hash` column (only the hash is stored, never the
raw token). Cross-Auth passes user ids to the session layer as strings
(`login(user_id: str)`), but the adapter coerces them to your `user_id` column's
type — declare it as `str`, `int`, or `UUID` to match your user table's primary
key, so you keep a real foreign key:

```python
from datetime import datetime

from sqlmodel import Field, SQLModel

from cross_auth import session_status


class UserSession(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    token_hash: str = Field(index=True)
    user_id: int = Field(foreign_key="user.id", index=True)
    created_at: datetime
    updated_at: datetime
    expires_at: datetime
    last_active_at: datetime | None = None
    revoked_at: datetime | None = None
    client_id: str | None = None
    client_name: str | None = None
    user_agent: str | None = None
    ip: str | None = None

    @property
    def status(self):
        return session_status(self)
```

`session_status` is the canonical active/expired/revoked derivation — delegate
to it rather than re-implementing the state machine, so your records always
agree with the adapter's status filters.

```python
from cross_auth.storage.sqlmodel import SQLModelSessionStorage

session_storage = SQLModelSessionStorage(
    UserSession, session_factory=lambda: Session(engine)
)
```

To override behaviour, subclass and declare the model as a class attribute
instead:

```python
class SessionStore(SQLModelSessionStorage[UserSession]):
    SessionModel = UserSession
```

Datetime columns may be plain (timezone-naive) as above — values are stored as
UTC wall time and come back timezone-aware UTC, regardless of the database
connection's time zone — or declared with `DateTime(timezone=True)` if you
prefer `timestamptz` columns.

#### Pagination cursors

`list_for_user` pages with opaque keyset cursors. A cursor is bound to the
`order_by` it was minted under; replaying it with a different ordering, or
sending a malformed cursor, raises `InvalidCursorError` (a `ValueError` subclass
from `cross_auth.exceptions`) — map it to a 400 in your session-listing
endpoint:

```python
from cross_auth.exceptions import InvalidCursorError

try:
    result = auth.list_sessions(user_id, cursor=cursor)
except InvalidCursorError:
    raise HTTPException(status_code=400, detail="Invalid cursor")
```

### The session factory

Both SQLModel adapters take a `session_factory` rather than a live `Session`. A
SQLModel `Session` is a short-lived unit of work, while a `CrossAuth` instance
usually lives for the whole application - accepting one shared session would
make it easy to leak a session across requests. The factory must return a fresh
`Session` each call:

```python
SQLModelSessionStorage(UserSession, session_factory=lambda: Session(engine))
```

The adapter opens a session per operation (with `expire_on_commit=False`, so
committed rows keep their loaded values) and closes it before returning. When
`social_accounts` is a relationship, user queries eager-load it, so returned
instances remain safe to read after their session closes; a plain
`social_accounts` property works too. If your models carry additional lazy
relationships, load them yourself (`create_user` and the finders only guarantee
scalar columns and `social_accounts`).

## Implementing the protocols directly

For ORMs without a built-in adapter, implement the protocols on your own
objects. You don't inherit from anything — Cross-Auth accepts any object with
the right methods.

### SecondaryStorage

```python
class SecondaryStorage(Protocol):
    def set(self, key: str, value: str, ttl: int | None = None): ...
    def get(self, key: str) -> str | None: ...
    def delete(self, key: str): ...
    def pop(self, key: str) -> str | None: ...
```

**Implementations must honor `ttl`** (seconds until expiry). For some keys — the
OAuth authorization-request state, in particular — the TTL is the only expiry
mechanism: an implementation that ignores it leaves abandoned login state around
forever. `RedisStorage` enforces it natively via Redis `EX`; a hand-rolled
in-memory store must track and check expiry itself. The example app's
`MemorySecondaryStorage` (`examples/fastapi/main.py`) shows the pattern.

### AccountsStorage

```python
class AccountsStorage(Protocol):
    def find_user_by_email(self, email: str) -> User | None: ...
    def find_user_by_id(self, id: Any) -> User | None: ...
    def find_social_account(
        self, *, provider: str, provider_user_id: str
    ) -> SocialAccount | None: ...
    def find_social_account_by_id(
        self, social_account_id: Any
    ) -> SocialAccount | None: ...
    def list_social_accounts(self, *, user_id: Any) -> Iterable[SocialAccount]: ...
    def create_user(
        self,
        *,
        user_info: dict[str, Any],
        email: str,
        email_verified: bool,
        extra_fields: Mapping[str, Any] | None = None,
    ) -> User: ...
    def create_social_account(self, **kwargs) -> SocialAccount: ...
    def update_social_account(self, social_account_id, **kwargs) -> SocialAccount: ...
    def delete_social_account(self, social_account_id: Any) -> None: ...
```

The user and social-account write methods receive `extra_fields`, mappings
populated by the corresponding `user.create`, `social_account.create`, or
`social_account.update` hook. Built-in SQLModel storage writes those keys as
additional mapped columns; custom storage implementations should persist the
keys they support and reject unknown ones.

Emails are normalized before they reach your storage: Cross-Auth trims and
lowercases them ahead of every `find_user_by_email` and `create_user` call, so
implementations can compare exactly against the stored (lowercase) value. Pass
`normalize_email=` to `CrossAuth` to customize this — e.g. to also collapse
Gmail dot-aliases.

Your user model must expose these attributes. Cross-Auth only ever reads them
(the protocols declare read-only properties), so your model may narrow an
optional type — a non-nullable `provider_email_verified: bool` on a social
account, for example — and plain columns, properties, or ORM attributes all
qualify:

```python
class User(Protocol):
    id: Any
    email: str | None
    email_verified: bool
    hashed_password: str | None

    @property
    def has_usable_password(self) -> bool: ...

    @property
    def social_accounts(self) -> Iterable[SocialAccount]: ...
```

### SessionStorage

Browser session cookies and OAuth bearer tokens both contain opaque session
tokens; only the token hash is stored.

```python
class SessionRecord(Protocol):
    id: Any
    user_id: Any
    created_at: AwareDatetime
    updated_at: AwareDatetime
    expires_at: AwareDatetime
    last_active_at: AwareDatetime | None
    revoked_at: AwareDatetime | None
    client_id: str | None
    client_name: str | None
    user_agent: str | None
    ip: str | None

    @property
    def status(self) -> Literal["active", "expired", "revoked"]: ...


class SessionListResult(Protocol):
    records: Sequence[SessionRecord]
    next_cursor: str | None


class SessionStorage(Protocol):
    def create(
        self,
        *,
        token_hash: str,
        user_id: Any,
        created_at: AwareDatetime,
        updated_at: AwareDatetime,
        expires_at: AwareDatetime,
        client_id: str | None = None,
        client_name: str | None = None,
        user_agent: str | None = None,
        ip: str | None = None,
        last_active_at: AwareDatetime | None = None,
    ) -> SessionRecord: ...

    def get(self, *, token_hash: str, now: AwareDatetime) -> SessionRecord | None: ...
    def get_any(self, session_id: Any) -> SessionRecord | None: ...
    def refresh(self, session_id: Any, **kwargs) -> SessionRecord | None: ...
    def revoke(self, session_id: Any, *, revoked_at: AwareDatetime) -> None: ...
    def list_for_user(self, user_id: Any, **kwargs) -> SessionListResult: ...
    def revoke_all_for_user(self, user_id: Any, **kwargs) -> int: ...
```

If `list_for_user` supports cursor pagination, raise
`cross_auth.exceptions.InvalidCursorError` for malformed or mismatched cursors,
so applications can handle bad cursors the same way for every backend.

`session_storage` is optional when constructing `CrossAuth`, but session-backed
features require it. `login()`, `logout()`, and session-management methods raise
clearly when no `session_storage` is configured. The built-in `/token` endpoint
is still registered, but successful token issuance requires `session_storage`.
