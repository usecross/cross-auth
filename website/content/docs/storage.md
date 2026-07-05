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

`RedisStorage` implements `SecondaryStorage`. Pass it an existing redis client:

```python
import redis
from cross_auth.storage.redis import RedisStorage

secondary_storage = RedisStorage(redis.Redis.from_url("redis://localhost:6379"))
```

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
`AccountsStorage`, including a working `create_user`. App-specific signup
behaviour (invite checks, team creation, profile defaults) goes in the optional
`on_signup` hook.

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

Real signup flows usually do more. Three hooks cover the phases of that
transaction:

- `build_user` **constructs** the instance. The default is
  `UserModel(email=..., email_verified=...)` — override it when your model needs
  more: generated fields (a unique username — the open session is provided for
  lookups), or a differently-named column. This matters because SQLModel
  silently ignores unknown constructor kwargs: a model that stores verification
  under, say, `is_verified` must be constructed explicitly here or the flag is
  silently lost.
- `on_signup` runs **inside the transaction**, after the user is added but
  before the commit. Raise to abort (everything rolls back), mutate `user` to
  fill extra columns, or `session.add(...)` related rows so the whole signup
  commits atomically. The user isn't flushed yet, so call `session.flush()` if
  you need `user.id`.
- `after_signup` runs **post-commit** with the final, fully-loaded user —
  telemetry, welcome emails, queueing background work. Raising here does not
  undo the signup.

```python
class AccountsStore(SQLModelAccountsStorage[User, SocialAccount]):
    UserModel = User
    SocialAccountModel = SocialAccount

    def build_user(self, *, session, user_info, email, email_verified):
        username = generate_unique_username(session, email)
        return User(email=email, is_verified=email_verified, username=username)

    def on_signup(self, *, session, user, user_info, email_verified):
        if not is_invited(user.email):
            # Aborts the signup: the transaction rolls back,
            # nothing is persisted.
            raise CrossAuthException("signup_not_allowed", "Invite only")
        user.full_name = user_info.get("name")  # set extra columns
        session.add(Team(owner=user))  # joins the same commit

    def after_signup(self, *, user, user_info):
        telemetry.capture("account_created", user_id=user.id)


accounts_storage = AccountsStore(session_factory=lambda: Session(engine))
```

Everything else (`find_user_by_email`, `find_social_account`,
`create_social_account`, `update_social_account`, `delete_social_account`, and
the rest) is handled by the base.

Configuration is validated at construction: a missing model declaration, a model
missing an attribute the `User`/`SocialAccount` protocols require, or a
non-callable `session_factory` raises a `TypeError` at startup rather than on
the first login. The token columns the default payload builders write
(`access_token`, `refresh_token`, their expiries, and `scope`) are checked too,
because SQLModel silently ignores unknown constructor kwargs — without the
check, a missing column would silently drop OAuth tokens. If you don't want to
store tokens, override both payload builders to drop those fields.

#### Customization hooks

Override these methods instead of reimplementing whole protocol methods:

- `build_user(*, session, user_info, email, email_verified)` - construct the
  user instance (see above).
- `on_signup(*, session, user, user_info, email_verified)` - signup behaviour
  inside the signup transaction (see above).
- `after_signup(*, user, user_info)` - post-commit side effects (see above).
- `filter_user_query(statement)` - refine user lookups, e.g. exclude
  soft-deleted users. (`create_user` deliberately skips this filter.)
- `filter_social_account_query(statement)` - scope social accounts, e.g. by
  tenant. Applied to reads **and** writes, so a scoped store can't be made to
  update or delete rows its lookups would never return. It does **not** apply to
  the eager-loaded `user.social_accounts` relationship on a returned user — that
  collection is always loaded unfiltered; use `list_social_accounts` for a
  filtered read.
- `build_social_account_create_values(*, user_info, **fields)` - customize the
  columns written when creating a social account (e.g. derive a provider
  username from `user_info`).
- `build_social_account_update_values(*, user_info, record, **fields)` - same,
  for updates. `record` is the loaded row being updated, so derived columns can
  read its current state (e.g. recompute a provider username from
  `record.provider` and `record.provider_user_id`).

```python
class AccountsStore(SQLModelAccountsStorage[User, SocialAccount]):
    UserModel = User
    SocialAccountModel = SocialAccount

    def filter_user_query(self, statement):
        # Assumes your User model adds a deleted_at column.
        return statement.where(User.deleted_at == None)  # noqa: E711
```

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
        self, *, user_info: dict[str, Any], email: str, email_verified: bool
    ) -> User: ...
    def create_social_account(self, **kwargs) -> SocialAccount: ...
    def update_social_account(self, social_account_id, **kwargs) -> SocialAccount: ...
    def delete_social_account(self, social_account_id: Any) -> None: ...
```

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
