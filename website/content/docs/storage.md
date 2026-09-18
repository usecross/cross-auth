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
`AccountsStorage`, including atomic user and identity creation. Map app-specific
user columns with the public typed hooks described below. Use the public
`build_user` extension when required application rows must share the signup
transaction.

Define your tables by inheriting `SQLModelUser` and `SQLModelSocialAccount`. The
bases supply common auth fields; you still control table names, primary keys,
foreign keys, identity constraints, and migrations. User verification may be a
column or writable property. Social accounts may be a relationship or property,
or may be omitted entirely when account access goes through the adapter's
storage queries. Credential fields may be columns or properties when excluded
from writes.

```python
from datetime import datetime

from sqlalchemy import UniqueConstraint
from sqlmodel import Field, Relationship

from cross_auth.storage.sqlmodel import SQLModelSocialAccount, SQLModelUser


class SocialAccount(SQLModelSocialAccount, table=True):
    __table_args__ = (UniqueConstraint("provider", "provider_user_id"),)

    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id")
    access_token: str | None = None
    refresh_token: str | None = None
    access_token_expires_at: datetime | None = None
    refresh_token_expires_at: datetime | None = None
    scope: str | None = None

    user: "User" = Relationship(back_populates="social_accounts")


class User(SQLModelUser, table=True):
    id: int | None = Field(default=None, primary_key=True)
    email: str = Field(index=True, unique=True)
    email_verified: bool = False

    social_accounts: list[SocialAccount] = Relationship(
        back_populates="user", sa_relationship_kwargs={"lazy": "selectin"}
    )
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

`create_user_with_identity` saves the new user, provider identity, and required
application rows in one adapter-owned transaction. If any part fails, all of
those writes roll back. It returns both records fully loaded, so they stay
readable after the session closes. Like standalone `create_user`, it bypasses
`filter_user_query` when returning the newly created user.

The default user creation validates and applies mapped `extra_fields` from the
`user.create` hook, then assigns `email_verified` through the model attribute.
That supports either a mapped field or a writable property backed by a
differently named column.

Use `@auth.before("user.create")` for signup policy and mapped app fields,
`@auth.after("user.create")` for post-commit work such as telemetry or welcome
emails. Those are public lifecycle hooks and apply regardless of the storage
implementation.

If related rows must commit atomically with the user, subclass the adapter and
override its public `build_user` method. Existing `_build_user` overrides remain
supported, but new code should use `build_user`. Call `super()`, add your rows
to the supplied session, and return the user. Do not commit or perform external
I/O here; the adapter owns the transaction boundary. During signup, these rows
commit together with the provider identity.

```python
class AccountsStore(SQLModelAccountsStorage[User, SocialAccount]):
    UserModel = User
    SocialAccountModel = SocialAccount

    def build_user(self, *, session, **kwargs):
        user = super().build_user(session=session, **kwargs)
        session.add(Team(owner=user))  # joins the same commit
        return user


accounts_storage = AccountsStore(session_factory=lambda: Session(engine))
```

When upgrading a SQLModel subclass, move customization from `create_user` to
`build_user`, and from `create_social_account` to the typed social-account
hooks. Atomic signup does not call those standalone creation methods, because
each commits its own transaction. Existing `_build_user` overrides still run.

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
  update or delete rows its lookups would never return. This filter does not
  apply to ORM relationships loaded by the application; use
  `list_social_accounts` for a filtered read.

For related rows that must share signup's transaction, the public `build_user`
extension point is described above. Prefer typed hooks for everything that does
not need the SQLModel session.

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
filtering. No storage subclass is needed unless you want to override behaviour.

Inherit `SQLModelSession` to get the timestamps, client metadata, internal
`token_hash` column, and computed `status` property. Only the hash is stored,
never the raw token. Define your own primary key and user ID column:

```python
from sqlmodel import Field

from cross_auth.storage.sqlmodel import SQLModelSession


class UserSession(SQLModelSession, table=True):
    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id", index=True)
```

Cross-Auth passes user IDs to the session layer as strings
(`login(user_id: str)`), but the adapter coerces them to your column's type.
Declare `user_id` as `str`, `int`, or `UUID` to match your user table's primary
key. Override inherited fields when you need different indexes, database column
names, or timezone-aware types. The inherited `status` property delegates to
`session_status`, so it agrees with the adapter's active/expired/revoked
filters.

**Migration:** existing tables must inherit the corresponding base instead of
`SQLModel`. Existing field declarations can remain as overrides; this
inheritance change does not require a database migration when the resulting
columns and indexes are unchanged. The adapter checks inheritance and required
attributes at construction. IDs, relationships, verification, and credential
properties remain application-defined and are checked at startup. A user
relationship for social accounts is optional; use `list_social_accounts` when
the user model does not declare one.

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
committed rows keep their loaded values) and closes it before returning. The
adapter does not change relationship loading: configure a relationship such as
`social_accounts` with SQLAlchemy's `lazy="selectin"` when returned users must
read it after the session closes. A model may omit the relationship entirely;
use `list_social_accounts` for account access in that case. If your models carry
other lazy relationships, configure or load them yourself.

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

**Implementations must honor `ttl`** (seconds until expiry). The callback checks
its stored authorization-request expiry too, but storage TTL is still needed to
remove abandoned state and expire other temporary records. `RedisStorage`
enforces it natively via Redis `EX`; a hand-rolled in-memory store must track
and check expiry itself. The example app's `MemorySecondaryStorage`
(`examples/fastapi/main.py`) shows the pattern.

### Connection ownership and migration

Match database constraints to `account_linking.allow_shared_connections`, which
defaults to `False`. Cross-Auth checks the policy before creation; the database
constraints enforce it when requests run concurrently. No explicit table lock is
required. The same schema rules can be implemented by SQLModel, Django, or
another storage adapter.

There is currently no automatic check that the flag and schema agree. Setting
`False` with a shared schema rejects observed conflicts but cannot prevent two
concurrent first connections. Setting `True` with an exclusive schema still
causes the database to reject sharing.

#### Exclusive ownership (default example)

Require unique `(provider, provider_user_id)`. Each provider identity belongs to
one application user, whether it is connected for API access or enabled for
login. The SQLModel example above uses this constraint:

```python
__table_args__ = (UniqueConstraint("provider", "provider_user_id"),)
```

#### Shared integration connections

Replace global identity uniqueness with both of these rules:

- Unique `(user_id, provider, provider_user_id)` for every connection.
- Unique `(provider, provider_user_id)` where `is_login_method` is true.

For PostgreSQL and SQLite, use the following table arguments instead:

```python
from sqlalchemy import Index, UniqueConstraint, text

__table_args__ = (
    UniqueConstraint("user_id", "provider", "provider_user_id"),
    Index(
        "uq_social_account_login_identity",
        "provider",
        "provider_user_id",
        unique=True,
        postgresql_where=text("is_login_method"),
        sqlite_where=text("is_login_method = 1"),
    ),
)
```

The partial index applies only to login-enabled rows. Integration-only rows may
share an identity across users, but sign-in still has exactly one owner at most.
Both constraints must be installed in the database before enabling sharing,
including promotion through `update_social_account(enable_login=True)`.
Declaring indexes on a model does not migrate an existing table. Shared schemas
without these constraints are unsupported: they cannot guarantee a single login
owner during attachment or promotion. For other databases, use an equivalent
schema that enforces both rules before supporting sharing.

Provider IDs must consistently identify a provider configuration and its subject
namespace. Do not reuse an ID for different issuers whose subjects can overlap.
Ownership is global within the social-account table, even when an adapter
applies query filters for tenants or soft deletion. Tenant filters do not create
separate login ownership.

#### Migrating existing tables

Application-owned tables need an explicit migration. `create_all()` does not add
constraints to existing tables. Adapt these checks to your table/column names:

```sql
-- Must be empty for exclusive ownership.
SELECT provider, provider_user_id, COUNT(*)
FROM socialaccount
GROUP BY provider, provider_user_id
HAVING COUNT(*) > 1;

-- Must be empty for shared connections: duplicates for the same user.
SELECT user_id, provider, provider_user_id, COUNT(*)
FROM socialaccount
GROUP BY user_id, provider, provider_user_id
HAVING COUNT(*) > 1;

-- Must be empty for shared connections: multiple login owners.
SELECT provider, provider_user_id, COUNT(*)
FROM socialaccount
WHERE is_login_method = TRUE
GROUP BY provider, provider_user_id
HAVING COUNT(*) > 1;
```

Stop if a query required for your chosen schema returns rows. Resolve those
records deliberately before adding constraints; do not merge users or reassign
credentials automatically. Keep identity columns and `is_login_method` non-null.

For a table named `socialaccount`, exclusive ownership uses:

```sql
CREATE UNIQUE INDEX uq_socialaccount_identity
ON socialaccount (provider, provider_user_id);
```

Shared connections use these two indexes instead:

```sql
CREATE UNIQUE INDEX uq_socialaccount_user_identity
ON socialaccount (user_id, provider, provider_user_id);

CREATE UNIQUE INDEX uq_socialaccount_login_identity
ON socialaccount (provider, provider_user_id)
WHERE is_login_method = TRUE;
```

When moving from exclusive to shared ownership, add the two new constraints and
upgrade all writers before removing global identity uniqueness and enabling
`allow_shared_connections`. When moving back, resolve all duplicate identities
first, then restore global uniqueness. Coordinate migrations with writers so
duplicates cannot appear between checks and constraint creation. Older code
assumes a single connection globally and must not run against shared identities.

#### Concurrent attachment

The adapter attempts an insert and lets the database enforce ownership. On an
`IntegrityError`, it rolls back and looks for the same user's connection. If
found, it returns that row unchanged, ignoring the supplied creation values. An
attempt to promote that row to a login method still raises
`CrossAuthException("account_already_linked")`.

If no matching connection exists, the original `IntegrityError` propagates. The
adapter does not inspect driver error codes or constraint names to distinguish
ownership conflicts from other integrity failures. Applications that want a
specific HTTP response for these failures must handle them at their boundary.

Use the ordinary authenticated update flow to refresh credentials. Storage
idempotency does not guarantee exactly-once hook delivery; creation hooks can
run for concurrent attempts that resolve to the same connection.

Supply a fresh session from `session_factory`. Concurrent SQLite requests need
separate database connections, such as a file-backed database with a pool, or
external serialization when sharing a single connection. Constraint enforcement
applies to direct SQL writes as well as adapter calls.

Sign-in rejects an identity when it observes connections but no login owner.
This lookup does not lock the identity: with the shared schema, a first login
and another user's integration connection can be created concurrently. The
database still guarantees one login owner and one connection per user.
Cross-Auth never promotes an existing integration-only row through creation.

New-user signup saves the user and identity in one transaction. A losing
concurrent signup rolls back its user and related rows, and may propagate the
backend integrity error. No automatic retry or account linking follows that
failure.

### Safe account disconnection

User-facing disconnects call `disconnect_social_account`, which checks the
current stored credentials and deletes the selected connection in one
transaction. The operation returns one of three `DisconnectResult` values:

- `disconnected`: the deletion committed.
- `not_found`: the user or account is unavailable, or the account does not match
  the supplied user and provider.
- `last_login_method`: removing this login-enabled identity would leave no
  usable password or other login-enabled identity.

Integration-only connections can always be removed without affecting this
policy, but they do not count as alternative login methods. Password eligibility
comes from the user model's `has_usable_password` property; custom models must
return false for absent or unusable credentials.

Custom adapters must serialize disconnects for the same user, reread the current
records, check the alternatives, and delete inside the same transaction. A
separate lookup followed by deletion is unsafe: two requests can each remove the
last remaining alternative. ORM transaction details stay inside the adapter.

SQLModel requires a session with transactions enabled; engine or DBAPI
`AUTOCOMMIT` mode is unsupported. It reserves the user row with an update before
reading the credentials. PostgreSQL serializes concurrent updates to that row;
SQLite serializes writers. The update preserves column values, including
SQLAlchemy `onupdate` columns, but database UPDATE triggers still run and must
tolerate it.

SQLite can raise a lock-timeout error under contention. PostgreSQL transactions
at repeatable-read or serializable isolation can raise serialization failures.
Such failures roll back; the library does not retry them automatically. Retry
the whole operation after contention clears, rather than continuing a failed
transaction.

This guarantee applies to calls through `disconnect_social_account`. The
low-level `delete_social_account` method remains available for application-owned
cleanup and deliberately skips the last-login check. There is no administrative
bypass on the HTTP disconnect routes. Custom password removal, login-method
changes, or direct database deletes must coordinate with the same user record if
they need to preserve this guarantee across those operations too.

### AccountsStorage

```python
class AccountsStorage(Protocol):
    def find_user_by_email(self, email: str) -> User | None: ...
    def find_user_by_id(self, id: Any) -> User | None: ...
    def find_social_account(
        self,
        *,
        provider: str,
        provider_user_id: str,
        user_id: Any | None = None,
        is_login_method: bool | None = None,
    ) -> SocialAccount | None: ...
    def has_social_account(self, *, provider: str, provider_user_id: str) -> bool: ...
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
    def create_user_with_identity(
        self,
        *,
        user: UserCreate,
        identity: Callable[[User], SocialAccountCreate],
    ) -> tuple[User, SocialAccount]: ...
    def create_social_account(self, **kwargs) -> SocialAccount: ...
    def update_social_account(self, social_account_id, **kwargs) -> SocialAccount: ...
    def disconnect_social_account(
        self, *, user_id: Any, provider: str, social_account_id: Any
    ) -> DisconnectResult: ...
    def delete_social_account(self, social_account_id: Any) -> None: ...
```

Identity lookups should specify `user_id` for a user's connection or
`is_login_method=True` for the login owner. An unfiltered identity lookup that
matches multiple rows raises rather than selecting an arbitrary user.
`has_social_account` checks global existence, including rows hidden by query
filters, so a connected-only or hidden identity cannot accidentally create a new
login owner. Custom adapters must implement the new filters and existence
method. Their schemas and creation methods must enforce the ownership contract
under concurrent writes.

`update_social_account` also receives `enable_login: bool = False`. When true,
enable login and update credentials in one atomic write, enforcing the same
single-login-owner constraint as creation. When false, leave the stored login
flag untouched so a credential refresh cannot undo a concurrent promotion.
Failed promotions must roll back credential changes as well. Database integrity
errors from racing promotions may propagate, as with racing attachments.

The SQLModel adapter relies on the required ownership constraints above; it does
not inspect the database schema. An existing login owner or a concurrent
promotion causes the database to reject the update and roll back its credential
changes. The Cross-Auth flow checks ownership before calling storage to report
an observed conflict as `account_already_linked`, but that lookup is not a
substitute for database uniqueness.

Custom adapters must implement `create_user_with_identity` atomically; calling
`create_user` and `create_social_account` with separate commits does not satisfy
this contract. `UserCreate` and `SocialAccountCreate` describe the write fields.
The `identity` callback receives the new user with its assigned ID and prepares
the identity fields, including the `before social_account.create` hook. Call it
once inside the transaction, then save the identity for that user. If the
callback or either write raises, roll back the whole signup.

This contract does not expose a transaction object to core. SQLModel uses its
session; a Django adapter can use `transaction.atomic()` and the same callback.
Provider HTTP requests happen before this operation. During new-user signup,
`before social_account.create` runs inside the transaction: the new user has an
ID but is not yet committed. Use this hook to validate or transform the supplied
fields; do not open another storage session to look up that user. Keep
before-create hooks free of external side effects, since the database
transaction can still fail.

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

`refresh` must atomically update only a session whose `revoked_at` is null and
whose current `expires_at` is at or after the supplied `updated_at`. This
matches `session_status`: a session is still active at the exact expiry instant.
Return `None` without changing the record if it is missing, revoked, or expired.
An omitted `last_active_at` preserves the stored value.

The SQLModel adapter enforces this with a conditional database update. Custom
adapters must provide the same guarantee: a separate active-session lookup
followed by an unconditional update allows revocation to race the refresh.
Callers must supply the current time as `updated_at`; core reads the clock again
after the initial lookup before attempting a sliding refresh.

If `list_for_user` supports cursor pagination, raise
`cross_auth.exceptions.InvalidCursorError` for malformed or mismatched cursors,
so applications can handle bad cursors the same way for every backend.

`session_storage` is optional when constructing `CrossAuth`, but session-backed
features require it. `login()`, `logout()`, and session-management methods raise
clearly when no `session_storage` is configured. The built-in `/token` endpoint
is still registered, but successful token issuance requires `session_storage`.
