from __future__ import annotations

import uuid
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, ClassVar, Generic, TypeVar, overload

try:
    from sqlalchemy import BigInteger, SmallInteger, and_, inspect, or_, update
    from sqlalchemy.orm import selectinload
    from sqlmodel import SQLModel, Session, select
    from sqlmodel.sql.expression import SelectOfScalar
except ImportError as exc:  # pragma: no cover - exercised only without the extra
    raise ImportError(
        "cross_auth.storage.sqlmodel requires SQLModel. "
        "Install it with: pip install 'cross-auth[sqlmodel]'"
    ) from exc

from cross_auth._storage import SessionListOrder, SessionStatus
from cross_auth.exceptions import InvalidCursorError
from cross_auth.storage._cursor import decode_cursor, encode_cursor

SessionModelT = TypeVar("SessionModelT", bound=SQLModel)
UserModelT = TypeVar("UserModelT", bound=SQLModel)
SocialAccountModelT = TypeVar("SocialAccountModelT", bound=SQLModel)

_ORDER_FIELDS: dict[SessionListOrder, tuple[str, bool]] = {
    # order_by -> (attribute name, descending?)
    "updated_at_desc": ("updated_at", True),
    "updated_at_asc": ("updated_at", False),
    "created_at_desc": ("created_at", True),
    "created_at_asc": ("created_at", False),
    "expires_at_desc": ("expires_at", True),
    "expires_at_asc": ("expires_at", False),
}

_SESSION_DATETIME_FIELDS = (
    "created_at",
    "updated_at",
    "expires_at",
    "last_active_at",
    "revoked_at",
)

_SOCIAL_ACCOUNT_DATETIME_FIELDS = (
    "access_token_expires_at",
    "refresh_token_expires_at",
)

# Write-only columns the adapter populates by default, beyond the
# protocol fields already checked via _required_models. SQLModel table models
# silently ignore unknown constructor kwargs, so without this check a missing
# column would silently drop OAuth tokens instead of failing.
_SOCIAL_ACCOUNT_WRITE_FIELDS = (
    "access_token",
    "refresh_token",
    "access_token_expires_at",
    "refresh_token_expires_at",
    "scope",
)

_SOCIAL_ACCOUNT_STANDARD_FIELDS = frozenset(
    {
        "user_id",
        "provider",
        "provider_user_id",
        "access_token",
        "refresh_token",
        "access_token_expires_at",
        "refresh_token_expires_at",
        "scope",
        "provider_email",
        "provider_email_verified",
        "is_login_method",
    }
)

_USER_STANDARD_FIELDS = frozenset({"email", "email_verified"})

# Sentinel for ids that cannot possibly match the column type (e.g. "abc"
# against an integer primary key).
_NO_MATCH = object()


def _column(model: type[SQLModel], field: str) -> Any:
    # Resolve by the mapped attribute name, not ``__table__.columns`` — that
    # collection is keyed by the database column name, which diverges from the
    # attribute when a column is renamed via ``sa_column``. The mapper's column
    # collection is keyed by the attribute, so it resolves either way (and still
    # returns None for non-column attributes such as a ``status`` property).
    return inspect(model).columns.get(field)


def _bind_datetime(
    model: type[SQLModel], field: str, value: datetime | None
) -> datetime | None:
    """Normalize an inbound datetime for one of ``model``'s columns.

    Values are converted to UTC. For timezone-naive columns the tzinfo is then
    stripped so the UTC wall time is stored and compared as-is — otherwise
    PostgreSQL converts aware parameters through the connection's TimeZone
    before dropping the offset, silently shifting every stored timestamp.
    """
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    value = value.astimezone(timezone.utc)
    column = _column(model, field)
    if column is not None and not getattr(column.type, "timezone", False):
        return value.replace(tzinfo=None)
    return value


def _int_column_range(column_type: Any) -> tuple[int, int]:
    """Signed integer range representable by an int-typed column.

    BigInteger and SmallInteger both subclass Integer, so they must be
    checked before falling back to the plain-Integer (32-bit) range.
    """
    if isinstance(column_type, BigInteger):
        bits = 64
    elif isinstance(column_type, SmallInteger):
        bits = 16
    else:
        bits = 32
    return -(2 ** (bits - 1)), 2 ** (bits - 1) - 1


def _coerce_id(model: type[SQLModel], field: str, value: object) -> object:
    """Coerce an externally-supplied id to the column's Python type.

    HTTP path params arrive as strings; comparing a text parameter against an
    int or UUID column raises a database error on PostgreSQL (SQLite silently
    matches nothing). Returns ``_NO_MATCH`` when the value cannot possibly
    match any row, so callers can answer ``None`` instead of crashing.
    """
    column = _column(model, field)
    if column is None or value is None:
        return value
    try:
        python_type = column.type.python_type
    except NotImplementedError:
        return value
    if python_type is int:
        if isinstance(value, str):
            try:
                value = int(value)
            except ValueError:
                return _NO_MATCH
        if not isinstance(value, int):
            # e.g. a uuid.UUID id decoded from a crafted pagination cursor —
            # comparing it against an int column would otherwise reach the
            # database as `integer < uuid`, raising ProgrammingError on
            # PostgreSQL.
            return _NO_MATCH
        low, high = _int_column_range(column.type)
        if not (low <= value <= high):
            # Outside the column type's representable range: passed through,
            # this raises DataError (PostgreSQL) or OverflowError (SQLite) at
            # the driver instead of matching no row.
            return _NO_MATCH
        return value
    if python_type is uuid.UUID:
        if isinstance(value, str):
            try:
                return uuid.UUID(value)
            except ValueError:
                return _NO_MATCH
        if not isinstance(value, uuid.UUID):
            # e.g. an int id — comparing it against a UUID column would
            # otherwise reach the database as `uuid < integer`, raising
            # ProgrammingError on PostgreSQL.
            return _NO_MATCH
        return value
    if python_type is str and not isinstance(value, str):
        return str(value)
    return value


def _ensure_aware_datetime(value: object) -> object:
    if not isinstance(value, datetime) or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=timezone.utc)


@overload
def _prepare_record(record: None, fields: tuple[str, ...]) -> None: ...


@overload
def _prepare_record(
    record: SessionModelT, fields: tuple[str, ...]
) -> SessionModelT: ...


def _prepare_record(record, fields):
    """Label naive datetimes read back from the database as UTC."""
    if record is None:
        return None
    for field in fields:
        if hasattr(record, field):
            value = getattr(record, field)
            prepared_value = _ensure_aware_datetime(value)
            if prepared_value is not value:
                setattr(record, field, prepared_value)
    return record


class _SQLModelStorageBase:
    """Shared construction, validation, and session handling."""

    session_factory: Callable[[], Session]

    # (class attribute holding the model, attributes the model must expose).
    # Checked at construction so misconfiguration fails at startup with a
    # clear error instead of an AttributeError on the first auth request.
    _required_models: ClassVar[tuple[tuple[str, tuple[str, ...]], ...]] = ()

    # How to supply a missing model; session storage also accepts it in the
    # constructor and overrides this hint.
    _missing_model_hint: ClassVar[str] = (
        "declare a class attribute (e.g. `{attr} = MyModel`)"
    )

    def __init__(self, *, session_factory: Callable[[], Session]):
        if not callable(session_factory):
            raise TypeError(
                f"{type(self).__name__} session_factory must be a callable "
                f"returning a new Session, got {session_factory!r}"
            )
        self.session_factory = session_factory
        self._validate_models()

    def _validate_models(self) -> None:
        for attr, required_fields in self._required_models:
            # Instance lookup, so a model passed to the constructor (stored on
            # the instance) and one declared as a class attribute both resolve.
            model = getattr(self, attr, None)
            if not isinstance(model, type):
                raise TypeError(
                    f"{type(self).__name__} must be given the {attr} model — "
                    + self._missing_model_hint.format(attr=attr)
                )
            for field in required_fields:
                if not hasattr(model, field):
                    raise TypeError(
                        f"{model.__name__} is missing the {field!r} attribute "
                        f"required by {type(self).__name__}"
                    )

    @contextmanager
    def _open_session(self) -> Iterator[Session]:
        session = self.session_factory()
        # Keep loaded values after commit so returned instances stay readable
        # once the session closes. Only columns that were set in Python (or
        # eager-loaded) are guaranteed readable: a column populated purely by a
        # database server-side default is not re-fetched on create, so pass its
        # value explicitly if you need it on the returned record.
        session.expire_on_commit = False
        with session:
            yield session


def _prepare_session_record(record):
    return _prepare_record(record, _SESSION_DATETIME_FIELDS)


def _prepare_social_account(record):
    return _prepare_record(record, _SOCIAL_ACCOUNT_DATETIME_FIELDS)


class SQLModelSessionStorage(_SQLModelStorageBase, Generic[SessionModelT]):
    """Implements cross_auth.SessionStorage for a SQLModel model.

    Pass your session model to the constructor::

        store = SQLModelSessionStorage(
            UserSession, session_factory=lambda: Session(engine)
        )

    Or subclass (e.g. to override behaviour) and declare ``SessionModel``::

        class SessionStore(SQLModelSessionStorage[UserSession]):
            SessionModel = UserSession

    The model's datetime columns may be timezone-naive (values are stored as
    UTC wall time and labeled UTC when read back) or declared with
    ``DateTime(timezone=True)``. Configuration is validated at construction.
    """

    SessionModel: type[SessionModelT]

    _missing_model_hint = (
        "pass it to the constructor (e.g. `SQLModelSessionStorage(MySession, "
        "session_factory=...)`) or declare `SessionModel = MySession` on a "
        "subclass"
    )

    def __init__(
        self,
        model: type[SessionModelT] | None = None,
        *,
        session_factory: Callable[[], Session],
    ):
        if model is not None:
            self.SessionModel = model
        super().__init__(session_factory=session_factory)

    # The full cross_auth.SessionRecord protocol surface plus the internal
    # token_hash column. `status` is never read by the adapter itself, but the
    # protocol requires it — checking it here surfaces the missing property at
    # startup instead of when a session listing is first serialized.
    _required_models = (
        (
            "SessionModel",
            (
                "id",
                "token_hash",
                "user_id",
                "created_at",
                "updated_at",
                "expires_at",
                "last_active_at",
                "revoked_at",
                "client_id",
                "client_name",
                "user_agent",
                "ip",
                "status",
            ),
        ),
    )

    def create(
        self,
        *,
        token_hash: str,
        user_id: object,
        created_at: datetime,
        updated_at: datetime,
        expires_at: datetime,
        client_id: str | None = None,
        client_name: str | None = None,
        user_agent: str | None = None,
        ip: str | None = None,
        last_active_at: datetime | None = None,
    ) -> SessionModelT:
        model = self.SessionModel
        coerced_user_id = _coerce_id(model, "user_id", user_id)
        record = model(
            token_hash=token_hash,
            user_id=user_id if coerced_user_id is _NO_MATCH else coerced_user_id,
            created_at=_bind_datetime(model, "created_at", created_at),
            updated_at=_bind_datetime(model, "updated_at", updated_at),
            expires_at=_bind_datetime(model, "expires_at", expires_at),
            client_id=client_id,
            client_name=client_name,
            user_agent=user_agent,
            ip=ip,
            last_active_at=_bind_datetime(model, "last_active_at", last_active_at),
        )
        with self._open_session() as session:
            session.add(record)
            session.commit()
        return _prepare_session_record(record)

    def get(self, *, token_hash: str, now: datetime) -> SessionModelT | None:
        model = self.SessionModel
        now_bound = _bind_datetime(model, "expires_at", now)
        with self._open_session() as session:
            statement = select(model).where(
                getattr(model, "token_hash") == token_hash,
                getattr(model, "revoked_at") == None,  # noqa: E711
                # A session is active up to and including the expiry instant,
                # matching cross_auth.session_status.
                getattr(model, "expires_at") >= now_bound,
            )
            record = session.exec(statement).first()
        return _prepare_session_record(record)

    def get_any(self, session_id: object) -> SessionModelT | None:
        session_id = _coerce_id(self.SessionModel, "id", session_id)
        if session_id is _NO_MATCH:
            return None
        with self._open_session() as session:
            record = session.get(self.SessionModel, session_id)
        return _prepare_session_record(record)

    def list_for_user(
        self,
        user_id: object,
        *,
        now: datetime,
        status: SessionStatus | None = None,
        order_by: SessionListOrder = "updated_at_desc",
        limit: int = 50,
        cursor: str | None = None,
    ) -> _SessionListResult[SessionModelT]:
        if limit < 1:
            raise ValueError("limit must be >= 1")
        try:
            order_field, descending = _ORDER_FIELDS[order_by]
        except KeyError:
            raise ValueError(f"Unsupported order_by: {order_by!r}") from None
        model = self.SessionModel
        order_column = getattr(model, order_field)
        id_column = getattr(model, "id")
        now_bound = _bind_datetime(model, "expires_at", now)

        user_id = _coerce_id(model, "user_id", user_id)
        if user_id is _NO_MATCH:
            return _SessionListResult(records=[], next_cursor=None)

        with self._open_session() as session:
            statement = select(model).where(getattr(model, "user_id") == user_id)

            if status == "revoked":
                statement = statement.where(getattr(model, "revoked_at") != None)  # noqa: E711
            elif status == "active":
                statement = statement.where(
                    getattr(model, "revoked_at") == None,  # noqa: E711
                    getattr(model, "expires_at") >= now_bound,
                )
            elif status == "expired":
                statement = statement.where(
                    getattr(model, "revoked_at") == None,  # noqa: E711
                    getattr(model, "expires_at") < now_bound,
                )

            if cursor is not None:
                decoded = decode_cursor(cursor)
                if decoded.order_by != order_by:
                    raise InvalidCursorError(
                        f"Cursor was created with order_by="
                        f"{decoded.order_by!r}, not {order_by!r}"
                    )
                cursor_id = _coerce_id(model, "id", decoded.row_id)
                if cursor_id is _NO_MATCH:
                    raise InvalidCursorError("Invalid session pagination cursor")
                cursor_value = _bind_datetime(model, order_field, decoded.value)
                if descending:
                    boundary = or_(
                        order_column < cursor_value,
                        and_(
                            order_column == cursor_value,
                            id_column < cursor_id,
                        ),
                    )
                else:
                    boundary = or_(
                        order_column > cursor_value,
                        and_(
                            order_column == cursor_value,
                            id_column > cursor_id,
                        ),
                    )
                statement = statement.where(boundary)

            if descending:
                statement = statement.order_by(order_column.desc(), id_column.desc())
            else:
                statement = statement.order_by(order_column.asc(), id_column.asc())

            rows = session.exec(statement.limit(limit + 1)).all()

        has_more = len(rows) > limit
        records = [_prepare_session_record(record) for record in rows[:limit]]
        next_cursor = None
        if has_more and records:
            last = records[-1]
            next_cursor = encode_cursor(
                order_by, getattr(last, order_field), getattr(last, "id")
            )

        return _SessionListResult(records=records, next_cursor=next_cursor)

    def refresh(
        self,
        session_id: object,
        *,
        updated_at: datetime,
        expires_at: datetime,
        last_active_at: datetime | None = None,
    ) -> SessionModelT | None:
        model = self.SessionModel
        session_id = _coerce_id(model, "id", session_id)
        if session_id is _NO_MATCH:
            return None
        with self._open_session() as session:
            record = session.get(model, session_id)
            if record is None:
                return None
            record.updated_at = _bind_datetime(model, "updated_at", updated_at)
            record.expires_at = _bind_datetime(model, "expires_at", expires_at)
            if last_active_at is not None:
                record.last_active_at = _bind_datetime(
                    model, "last_active_at", last_active_at
                )
            session.add(record)
            session.commit()
        return _prepare_session_record(record)

    def revoke(self, session_id: object, *, revoked_at: datetime) -> None:
        model = self.SessionModel
        session_id = _coerce_id(model, "id", session_id)
        if session_id is _NO_MATCH:
            return
        with self._open_session() as session:
            statement = (
                update(model)
                .where(
                    getattr(model, "id") == session_id,
                    # Don't shift the audit timestamp of an already-revoked
                    # session.
                    getattr(model, "revoked_at") == None,  # noqa: E711
                )
                .values(revoked_at=_bind_datetime(model, "revoked_at", revoked_at))
            )
            session.exec(statement)  # type: ignore[call-overload]
            session.commit()

    def revoke_all_for_user(
        self,
        user_id: object,
        *,
        revoked_at: datetime,
        except_session_id: object | None = None,
    ) -> int:
        model = self.SessionModel
        user_id = _coerce_id(model, "user_id", user_id)
        if user_id is _NO_MATCH:
            return 0
        with self._open_session() as session:
            statement = (
                update(model)
                .where(
                    getattr(model, "user_id") == user_id,
                    getattr(model, "revoked_at") == None,  # noqa: E711
                )
                .values(revoked_at=_bind_datetime(model, "revoked_at", revoked_at))
            )
            if except_session_id is not None:
                except_session_id = _coerce_id(model, "id", except_session_id)
                # An id that can't match any row excludes nothing.
                if except_session_id is not _NO_MATCH:
                    statement = statement.where(
                        getattr(model, "id") != except_session_id
                    )
            result = session.exec(statement)  # type: ignore[call-overload]
            session.commit()
            return result.rowcount


@dataclass
class _SessionListResult(Generic[SessionModelT]):
    records: list[SessionModelT]
    next_cursor: str | None


class SQLModelAccountsStorage(
    _SQLModelStorageBase,
    Generic[UserModelT, SocialAccountModelT],
):
    """Implements cross_auth.AccountsStorage for SQLModel models.

    Pass your models to the constructor::

        store = SQLModelAccountsStorage(
            User, SocialAccount, session_factory=lambda: Session(engine)
        )

    Map app-specific user columns with the typed ``user.create`` hook's
    ``extra_fields``. For the rare case where related rows must join the same
    transaction, override the private ``_build_user`` escape hatch,
    call ``super()``, add the related rows, and return the user::

        class AccountsStore(SQLModelAccountsStorage[User, SocialAccount]):
            UserModel = User
            SocialAccountModel = SocialAccount

            def _build_user(self, *, session, **kwargs):
                user = super()._build_user(session=session, **kwargs)
                session.add(Team(owner=user))      # joins the same commit
                return user

    Use CrossAuth's typed ``user.create``, ``social_account.create``, and
    ``social_account.update`` hooks for lifecycle policy, side effects, and
    mapping provider-specific values onto extra columns. Override the query
    extension methods for behaviour such as
    excluding soft-deleted users or tenant scoping.
    ``filter_social_account_query`` is applied to reads
    and writes alike — except the eager-loaded ``user.social_accounts``
    relationship on a returned user, which is loaded unfiltered; go through
    ``list_social_accounts`` for a filtered read. Configuration is validated
    at construction.
    """

    UserModel: type[UserModelT]
    SocialAccountModel: type[SocialAccountModelT]
    excluded_social_account_fields: ClassVar[frozenset[str]] = frozenset()

    # The full cross_auth.User / cross_auth.SocialAccount protocol surfaces.
    # Core reads some of these mid-flow (e.g. has_usable_password during
    # account linking), so checking them here surfaces a non-compliant model
    # at startup instead of as an AttributeError halfway through an OAuth
    # login. Properties and relationships satisfy hasattr on the class.
    _required_models = (
        (
            "UserModel",
            (
                "id",
                "email",
                "email_verified",
                "hashed_password",
                "has_usable_password",
                "social_accounts",
            ),
        ),
        (
            "SocialAccountModel",
            (
                "id",
                "user_id",
                "provider",
                "provider_user_id",
                "provider_email",
                "provider_email_verified",
                "is_login_method",
                "access_token",
                "refresh_token",
                "access_token_expires_at",
                "refresh_token_expires_at",
                "scope",
            ),
        ),
    )

    _missing_model_hint = (
        "pass the models to the constructor (e.g. "
        "`SQLModelAccountsStorage(User, SocialAccount, session_factory=...)`) "
        "or declare `{attr} = MyModel` on a subclass"
    )

    def __init__(
        self,
        user_model: type[UserModelT] | None = None,
        social_account_model: type[SocialAccountModelT] | None = None,
        *,
        session_factory: Callable[[], Session],
    ):
        if user_model is not None:
            self.UserModel = user_model
        if social_account_model is not None:
            self.SocialAccountModel = social_account_model
        super().__init__(session_factory=session_factory)
        self._user_query_options = self._resolve_user_query_options()
        self._validate_social_account_write_fields()

    def _validate_social_account_write_fields(self) -> None:
        model = self.SocialAccountModel
        unsupported_exclusions = self.excluded_social_account_fields - set(
            _SOCIAL_ACCOUNT_WRITE_FIELDS
        )
        if unsupported_exclusions:
            raise TypeError(
                "excluded_social_account_fields only supports optional provider "
                f"credential fields; got {sorted(unsupported_exclusions)!r}"
            )
        missing = [
            field
            for field in _SOCIAL_ACCOUNT_WRITE_FIELDS
            if field not in self.excluded_social_account_fields
            and _column(model, field) is None
        ]
        if missing:
            raise TypeError(
                f"{model.__name__} is missing the {missing!r} mapped column(s) "
                f"written by {type(self).__name__}. SQLModel's constructor only "
                f"accepts pydantic fields — a property is not settable through "
                f"it, so these values would be silently lost. Add the columns."
            )

    def _check_social_account_values(self, values: dict[str, object]) -> None:
        model = self.SocialAccountModel
        unknown = [key for key in values if _column(model, key) is None]
        if unknown:
            raise TypeError(
                f"{model.__name__} has no mapped column(s) {unknown!r}, but "
                f"a social-account hook produced them. SQLModel's "
                f"constructor only accepts pydantic fields — a property is not "
                f"settable through it, so these values would be silently lost."
            )

    def _resolve_user_query_options(self) -> tuple[Any, ...]:
        # Eager-load social_accounts only when it is a mapped relationship;
        # the User protocol also allows it to be a plain property.
        model = self.UserModel
        if "social_accounts" in inspect(model).relationships:
            return (selectinload(getattr(model, "social_accounts")),)
        return ()

    def _find_user(self, *where: Any) -> UserModelT | None:
        model = self.UserModel
        with self._open_session() as session:
            statement = self.filter_user_query(
                select(model).where(*where).options(*self._user_query_options)
            )
            return session.exec(statement).first()

    def find_user_by_email(self, email: str) -> UserModelT | None:
        return self._find_user(getattr(self.UserModel, "email") == email)

    def find_user_by_id(self, id: object) -> UserModelT | None:
        id = _coerce_id(self.UserModel, "id", id)
        if id is _NO_MATCH:
            return None
        return self._find_user(getattr(self.UserModel, "id") == id)

    def create_user(
        self,
        *,
        user_info: dict[str, object],
        email: str,
        email_verified: bool,
        extra_fields: Mapping[str, object] | None = None,
    ) -> UserModelT:
        """Create a user in a single adapter-owned transaction.

        Builds and adds the user to the adapter-owned session, commits, and
        returns the user safe to read after the session closes (scalar columns
        loaded, ``social_accounts`` eager-loaded). Unlike ``find_user_by_id``
        this does not apply ``filter_user_query``, so a freshly created user is
        always returned.
        """
        model = self.UserModel
        with self._open_session() as session:
            user = self._build_user(
                session=session,
                user_info=user_info,
                email=email,
                email_verified=email_verified,
                extra_fields=extra_fields,
            )
            session.add(user)
            session.commit()
            statement = (
                select(model)
                .where(getattr(model, "id") == getattr(user, "id"))
                .options(*self._user_query_options)
            )
            user = session.exec(statement).one()
        return user

    def _find_social_account(self, *where: Any) -> SocialAccountModelT | None:
        model = self.SocialAccountModel
        with self._open_session() as session:
            statement = self.filter_social_account_query(select(model).where(*where))
            record = session.exec(statement).first()
        return _prepare_social_account(record)

    def find_social_account(
        self, *, provider: str, provider_user_id: str
    ) -> SocialAccountModelT | None:
        model = self.SocialAccountModel
        return self._find_social_account(
            getattr(model, "provider") == provider,
            getattr(model, "provider_user_id") == provider_user_id,
        )

    def find_social_account_by_id(
        self, social_account_id: object
    ) -> SocialAccountModelT | None:
        model = self.SocialAccountModel
        social_account_id = _coerce_id(model, "id", social_account_id)
        if social_account_id is _NO_MATCH:
            return None
        return self._find_social_account(getattr(model, "id") == social_account_id)

    def list_social_accounts(self, *, user_id: object) -> list[SocialAccountModelT]:
        model = self.SocialAccountModel
        user_id = _coerce_id(model, "user_id", user_id)
        if user_id is _NO_MATCH:
            return []
        with self._open_session() as session:
            statement = self.filter_social_account_query(
                select(model).where(getattr(model, "user_id") == user_id)
            )
            rows = list(session.exec(statement).all())
        return [_prepare_social_account(row) for row in rows]

    def create_social_account(
        self,
        *,
        user_id: object,
        provider: str,
        provider_user_id: str,
        access_token: str | None,
        refresh_token: str | None,
        access_token_expires_at: datetime | None,
        refresh_token_expires_at: datetime | None,
        scope: str | None,
        user_info: dict[str, object],
        provider_email: str | None,
        provider_email_verified: bool | None,
        is_login_method: bool,
        extra_fields: Mapping[str, object] | None = None,
    ) -> SocialAccountModelT:
        coerced_user_id = _coerce_id(self.SocialAccountModel, "user_id", user_id)
        values: dict[str, object] = {
            "user_id": user_id if coerced_user_id is _NO_MATCH else coerced_user_id,
            "provider": provider,
            "provider_user_id": provider_user_id,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "access_token_expires_at": access_token_expires_at,
            "refresh_token_expires_at": refresh_token_expires_at,
            "scope": scope,
            "provider_email": provider_email,
            "provider_email_verified": provider_email_verified,
            "is_login_method": is_login_method,
        }
        for field in self.excluded_social_account_fields:
            values.pop(field)
        self._merge_social_account_extra_fields(values, extra_fields)
        self._check_social_account_values(values)
        values = self._bind_social_account_datetimes(values)
        with self._open_session() as session:
            row = self.SocialAccountModel(**values)
            session.add(row)
            session.commit()
        return _prepare_social_account(row)

    def update_social_account(
        self,
        social_account_id: object,
        *,
        access_token: str | None,
        refresh_token: str | None,
        access_token_expires_at: datetime | None,
        refresh_token_expires_at: datetime | None,
        scope: str | None,
        user_info: dict[str, object],
        provider_email: str | None,
        provider_email_verified: bool | None,
        extra_fields: Mapping[str, object] | None = None,
    ) -> SocialAccountModelT:
        with self._open_session() as session:
            row = self._get_social_account_for_write(session, social_account_id)
            if row is None:
                raise ValueError(f"Social account {social_account_id!r} does not exist")
            values: dict[str, object] = {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "access_token_expires_at": access_token_expires_at,
                "refresh_token_expires_at": refresh_token_expires_at,
                "scope": scope,
                "provider_email": provider_email,
                "provider_email_verified": provider_email_verified,
            }
            for field in self.excluded_social_account_fields:
                values.pop(field)
            self._merge_social_account_extra_fields(values, extra_fields)
            self._check_social_account_values(values)
            values = self._bind_social_account_datetimes(values)
            for key, value in values.items():
                setattr(row, key, value)
            session.add(row)
            session.commit()
        return _prepare_social_account(row)

    def delete_social_account(self, social_account_id: object) -> None:
        with self._open_session() as session:
            row = self._get_social_account_for_write(session, social_account_id)
            if row is None:
                return
            session.delete(row)
            session.commit()

    def _get_social_account_for_write(
        self, session: Session, social_account_id: object
    ) -> SocialAccountModelT | None:
        # Writes go through filter_social_account_query too, so a store that
        # scopes lookups (e.g. by tenant) can't be made to mutate rows its
        # finds would never return.
        model = self.SocialAccountModel
        social_account_id = _coerce_id(model, "id", social_account_id)
        if social_account_id is _NO_MATCH:
            return None
        statement = self.filter_social_account_query(
            select(model).where(getattr(model, "id") == social_account_id)
        )
        return session.exec(statement).first()

    def _bind_social_account_datetimes(
        self, values: dict[str, object]
    ) -> dict[str, object]:
        model = self.SocialAccountModel
        return {
            key: _bind_datetime(model, key, value)
            if isinstance(value, datetime)
            else value
            for key, value in values.items()
        }

    @staticmethod
    def _merge_user_extra_fields(
        values: dict[str, object], extra_fields: Mapping[str, object] | None
    ) -> None:
        if not extra_fields:
            return
        conflicts = _USER_STANDARD_FIELDS & extra_fields.keys()
        if conflicts:
            fields = sorted(conflicts)
            raise ValueError(
                "user.create extra_fields cannot replace standard "
                f"field(s) {fields!r}; use the dedicated event field"
            )
        values.update(extra_fields)

    def _check_user_values(self, values: dict[str, object]) -> None:
        model = self.UserModel
        unknown = [key for key in values if _column(model, key) is None]
        if unknown:
            raise TypeError(
                f"{model.__name__} has no mapped column(s) {unknown!r}, but "
                f"a user.create hook produced them. SQLModel's constructor "
                f"only accepts pydantic fields — a property is not settable "
                f"through it, so these values would be silently lost."
            )

    @staticmethod
    def _merge_social_account_extra_fields(
        values: dict[str, object], extra_fields: Mapping[str, object] | None
    ) -> None:
        if not extra_fields:
            return
        conflicts = _SOCIAL_ACCOUNT_STANDARD_FIELDS & extra_fields.keys()
        if conflicts:
            fields = sorted(conflicts)
            raise ValueError(
                "social-account hook extra_fields cannot replace standard "
                f"field(s) {fields!r}; use the dedicated event field when writable"
            )
        values.update(extra_fields)

    def _build_user(
        self,
        *,
        session: Session,
        user_info: dict[str, object],
        email: str,
        email_verified: bool,
        extra_fields: Mapping[str, object] | None,
    ) -> UserModelT:
        """Construct the new user graph inside the adapter-owned session.

        The default applies hook-provided ``extra_fields`` to mapped columns,
        constructs ``UserModel``, then assigns ``email_verified`` through the
        model attribute. That assignment supports either a mapped field or a
        writable property backed by a differently-named column.

        This is a private escape hatch for apps that need related rows in the
        same transaction. Overrides should call ``super()``, add their related
        rows to ``session``, and return the user. Do not add or commit the user
        itself or perform external I/O; ``create_user`` owns those operations.
        """
        values: dict[str, object] = {"email": email}
        self._merge_user_extra_fields(values, extra_fields)
        self._check_user_values(values)
        user = self.UserModel(**values)
        try:
            setattr(user, "email_verified", email_verified)
        except AttributeError as exc:
            raise TypeError(
                f"{self.UserModel.__name__}.email_verified must be a mapped "
                "field or writable property"
            ) from exc
        return user

    def filter_user_query(
        self, statement: SelectOfScalar[UserModelT]
    ) -> SelectOfScalar[UserModelT]:
        """Customize user lookups, e.g. exclude soft-deleted users."""
        return statement

    def filter_social_account_query(
        self, statement: SelectOfScalar[SocialAccountModelT]
    ) -> SelectOfScalar[SocialAccountModelT]:
        """Customize social account reads and writes, e.g. tenant scoping.

        Not applied to the eager-loaded ``user.social_accounts`` relationship
        on a user returned by this store — that collection is loaded
        unfiltered; filtered reads must go through ``list_social_accounts``.
        """
        return statement
