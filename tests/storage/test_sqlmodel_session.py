import base64
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, cast

import pytest
import time_machine
from sqlmodel import Field, Session

from cross_auth._session import create_session, get_session
from cross_auth._storage import SessionStorage
from cross_auth.storage import InvalidCursorError
from cross_auth.storage.sqlmodel import SQLModelSession, SQLModelSessionStorage

from .models import (
    IntUserIdSessionStore,
    RenamedColumnSessionStore,
    SessionStore,
    TzAwareSessionStore,
    UserSession,
    UuidSessionStore,
)

NOW = datetime(2026, 6, 6, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def store(engine):
    return SessionStore(session_factory=lambda: Session(engine))


def _make(
    store,
    *,
    token_hash="hash",
    user_id="u1",
    created=NOW,
    updated=NOW,
    expires=None,
):
    return store.create(
        token_hash=token_hash,
        user_id=user_id,
        created_at=created,
        updated_at=updated,
        expires_at=expires or (NOW + timedelta(days=1)),
    )


@time_machine.travel(NOW)
def test_create_returns_usable_record(store):
    record = _make(store, token_hash="abc")

    # Readable after the session has closed (no DetachedInstanceError).
    assert record.id is not None
    assert record.token_hash == "abc"
    assert record.user_id == "u1"
    assert record.status == "active"


def test_get_active_by_token_hash(store):
    _make(store, token_hash="abc")

    record = store.get(token_hash="abc", now=NOW)

    assert record is not None
    assert record.token_hash == "abc"


def test_get_session_with_sliding_refresh_handles_naive_db_datetimes(store):
    session_storage = cast(SessionStorage, store)
    token, _ = create_session("u1", session_storage)

    session = get_session(token, session_storage, {"update_age": 0})

    assert session is not None
    assert session.updated_at.tzinfo is not None


def test_get_does_not_return_expired(store):
    _make(store, token_hash="abc", expires=NOW - timedelta(seconds=1))

    assert store.get(token_hash="abc", now=NOW) is None


def test_get_active_at_exact_expiry_instant(store):
    # Matches cross_auth.session_status: active up to and including expiry.
    _make(store, token_hash="abc", expires=NOW)

    assert store.get(token_hash="abc", now=NOW) is not None


def test_get_does_not_return_revoked(store):
    record = _make(store, token_hash="abc")
    store.revoke(record.id, revoked_at=NOW)

    assert store.get(token_hash="abc", now=NOW) is None


def test_get_missing_returns_none(store):
    assert store.get(token_hash="nope", now=NOW) is None


def test_get_any_returns_regardless_of_status(store):
    record = _make(store, token_hash="abc", expires=NOW - timedelta(days=1))
    store.revoke(record.id, revoked_at=NOW)

    fetched = store.get_any(record.id)

    assert fetched is not None
    assert fetched.id == record.id


def test_get_any_missing_returns_none(store):
    assert store.get_any(99999) is None


def test_get_any_coerces_string_ids(store):
    # Ids arrive as strings from HTTP path params; they must match the int
    # primary key instead of raising a database error (Postgres) or silently
    # matching nothing.
    record = _make(store)

    assert store.get_any(str(record.id)) is not None
    assert store.get_any("abc") is None


def test_get_any_out_of_range_id_returns_none(store):
    # An id outside the int column's representable range must answer None
    # rather than raising DataError (PostgreSQL) or OverflowError (SQLite).
    assert store.get_any(10**100) is None
    assert store.get_any("99999999999") is None


def test_refresh_updates_timestamps(store):
    record = _make(store)
    new_updated = NOW + timedelta(hours=1)
    new_expires = NOW + timedelta(days=2)

    refreshed = store.refresh(
        record.id,
        updated_at=new_updated,
        expires_at=new_expires,
        last_active_at=new_updated,
    )

    assert refreshed is not None
    assert refreshed.updated_at == new_updated
    assert refreshed.expires_at == new_expires

    # Re-read through a fresh session: the update must have been committed,
    # not just applied to the in-memory instance refresh() returned.
    persisted = store.get_any(record.id)
    assert persisted is not None
    assert persisted.updated_at == new_updated
    assert persisted.expires_at == new_expires
    assert persisted.last_active_at == new_updated


def test_refresh_preserves_last_active_at_when_omitted(store):
    record = store.create(
        token_hash="hash",
        user_id="u1",
        created_at=NOW,
        updated_at=NOW,
        expires_at=NOW + timedelta(days=1),
        last_active_at=NOW,
    )

    refreshed = store.refresh(
        record.id,
        updated_at=NOW + timedelta(hours=1),
        expires_at=NOW + timedelta(days=2),
    )

    assert refreshed is not None
    assert refreshed.last_active_at == NOW


def test_refresh_missing_returns_none(store):
    assert store.refresh(99999, updated_at=NOW, expires_at=NOW) is None


def test_revoke_one(store):
    record = _make(store)

    assert store.revoke(record.id, revoked_at=NOW) is True

    assert store.get_any(record.id).revoked_at is not None


def test_revoke_missing_is_noop(store):
    assert store.revoke(99999, revoked_at=NOW) is False
    # An uncastable id is also a no-op.
    assert store.revoke("abc", revoked_at=NOW) is False


def test_revoke_leaves_an_expired_session_expired(store):
    record = _make(store, expires=NOW - timedelta(days=1))

    assert store.revoke(record.id, revoked_at=NOW) is False

    stored = store.get_any(record.id)
    assert stored.revoked_at is None
    assert stored.status == "expired"


def test_revoke_twice_preserves_original_timestamp(store):
    record = _make(store)

    assert store.revoke(record.id, revoked_at=NOW) is True
    assert store.revoke(record.id, revoked_at=NOW + timedelta(hours=1)) is False

    assert store.get_any(record.id).revoked_at == NOW


def test_revoke_all_for_user(store):
    affected = _make(store, token_hash="a", user_id="u1")
    _make(store, token_hash="b", user_id="u1")
    _make(store, token_hash="c", user_id="u2")

    count = store.revoke_all_for_user("u1", revoked_at=NOW)

    assert count == 2
    assert store.get(token_hash="c", now=NOW) is not None
    # Re-read through a fresh session: the revocation must have been
    # committed, not just applied to the row objects the update touched.
    assert store.get_any(affected.id).revoked_at is not None


def test_revoke_all_except_one(store):
    keep = _make(store, token_hash="a", user_id="u1")
    _make(store, token_hash="b", user_id="u1")

    count = store.revoke_all_for_user("u1", revoked_at=NOW, except_session_id=keep.id)

    assert count == 1
    assert store.get_any(keep.id).revoked_at is None


def test_revoke_all_only_counts_active(store):
    record = _make(store, token_hash="a", user_id="u1")
    store.revoke(record.id, revoked_at=NOW)

    count = store.revoke_all_for_user("u1", revoked_at=NOW + timedelta(hours=1))

    assert count == 0


def test_revoke_all_leaves_expired_sessions_expired(store):
    active = _make(store, token_hash="a", user_id="u1")
    expired = _make(
        store, token_hash="b", user_id="u1", expires=NOW - timedelta(days=1)
    )
    # Still active at the exact expiry instant, like session_status.
    at_expiry = _make(store, token_hash="c", user_id="u1", expires=NOW)

    count = store.revoke_all_for_user("u1", revoked_at=NOW)

    assert count == 2
    assert store.get_any(active.id).status == "revoked"
    assert store.get_any(at_expiry.id).status == "revoked"
    assert store.get_any(expired.id).revoked_at is None


def test_list_by_status(store):
    active = _make(store, token_hash="a", user_id="u1")
    _make(store, token_hash="b", user_id="u1", expires=NOW - timedelta(days=1))
    revoked = _make(store, token_hash="c", user_id="u1")
    store.revoke(revoked.id, revoked_at=NOW)

    result = store.list_for_user("u1", now=NOW, status="active")

    ids = [r.id for r in result.records]
    assert ids == [active.id]


def test_list_ordering_created_at_asc(store):
    first = _make(store, token_hash="a", user_id="u1", created=NOW)
    second = _make(
        store, token_hash="b", user_id="u1", created=NOW + timedelta(hours=1)
    )

    result = store.list_for_user("u1", now=NOW, order_by="created_at_asc")

    assert [r.id for r in result.records] == [first.id, second.id]


@pytest.mark.parametrize(
    ("order_by", "expected"),
    [
        ("updated_at_desc", ["a", "b", "c"]),
        ("updated_at_asc", ["c", "b", "a"]),
        ("created_at_desc", ["c", "b", "a"]),
        ("created_at_asc", ["a", "b", "c"]),
        ("expires_at_desc", ["c", "a", "b"]),
        ("expires_at_asc", ["b", "a", "c"]),
    ],
)
def test_list_ordering_supported_values(store, order_by, expected):
    _make(
        store,
        token_hash="a",
        user_id="u1",
        created=NOW,
        updated=NOW + timedelta(minutes=2),
        expires=NOW + timedelta(days=20),
    )
    _make(
        store,
        token_hash="b",
        user_id="u1",
        created=NOW + timedelta(minutes=1),
        updated=NOW + timedelta(minutes=1),
        expires=NOW + timedelta(days=10),
    )
    _make(
        store,
        token_hash="c",
        user_id="u1",
        created=NOW + timedelta(minutes=2),
        updated=NOW,
        expires=NOW + timedelta(days=30),
    )

    result = store.list_for_user("u1", now=NOW, order_by=order_by)

    assert [r.token_hash for r in result.records] == expected


def test_list_rejects_non_positive_limit(store):
    with pytest.raises(ValueError):
        store.list_for_user("u1", now=NOW, limit=0)


def test_pagination_with_cursor(store):
    for i in range(5):
        _make(
            store,
            token_hash=f"t{i}",
            user_id="u1",
            updated=NOW + timedelta(minutes=i),
        )

    page1 = store.list_for_user("u1", now=NOW, order_by="updated_at_desc", limit=2)
    assert len(page1.records) == 2
    assert page1.next_cursor is not None

    page2 = store.list_for_user(
        "u1", now=NOW, order_by="updated_at_desc", limit=2, cursor=page1.next_cursor
    )
    assert len(page2.records) == 2

    seen = [r.token_hash for r in page1.records + page2.records]
    assert seen == ["t4", "t3", "t2", "t1"]
    assert page1.records[-1].token_hash != page2.records[0].token_hash


def test_pagination_breaks_ties_with_id(store):
    # All share the same updated_at; only the id tiebreaker separates them.
    ids = [
        _make(store, token_hash=f"t{i}", user_id="u1", updated=NOW).id for i in range(5)
    ]

    collected = []
    cursor = None
    for _ in range(3):
        page = store.list_for_user(
            "u1", now=NOW, order_by="updated_at_desc", limit=2, cursor=cursor
        )
        collected.extend(r.id for r in page.records)
        cursor = page.next_cursor
        if cursor is None:
            break

    assert sorted(collected) == sorted(ids)
    assert len(collected) == len(set(collected))  # no duplicates across pages


def test_pagination_supports_uuid_primary_keys(engine):
    store = UuidSessionStore(session_factory=lambda: Session(engine))
    for i in range(3):
        store.create(
            token_hash=f"t{i}",
            user_id="u1",
            created_at=NOW,
            updated_at=NOW + timedelta(minutes=i),
            expires_at=NOW + timedelta(days=1),
        )

    page1 = store.list_for_user("u1", now=NOW, limit=2)
    page2 = store.list_for_user("u1", now=NOW, limit=2, cursor=page1.next_cursor)

    assert page1.next_cursor is not None
    assert [record.token_hash for record in page1.records + page2.records] == [
        "t2",
        "t1",
        "t0",
    ]


def test_invalid_cursor_raises(store):
    _make(store, user_id="u1")

    with pytest.raises(InvalidCursorError):
        store.list_for_user("u1", now=NOW, cursor="not-a-valid-cursor")


def test_cursor_is_bound_to_its_order_by(store):
    for i in range(3):
        _make(
            store,
            token_hash=f"t{i}",
            user_id="u1",
            updated=NOW + timedelta(minutes=i),
        )
    page1 = store.list_for_user("u1", now=NOW, order_by="updated_at_desc", limit=2)

    with pytest.raises(InvalidCursorError):
        store.list_for_user(
            "u1", now=NOW, order_by="created_at_asc", cursor=page1.next_cursor
        )


def test_cursor_id_type_mismatch_raises_invalid_cursor(store):
    _make(store, user_id="u1")
    crafted = base64.urlsafe_b64encode(
        json.dumps(
            {"o": "updated_at_desc", "v": NOW.isoformat(), "id": "not-an-int"}
        ).encode()
    ).decode()

    with pytest.raises(InvalidCursorError):
        store.list_for_user("u1", now=NOW, cursor=crafted)


def test_crafted_cursor_uuid_id_against_int_pk_raises_invalid_cursor(store):
    # A uuid-shaped id (as decoded from a cursor built for a UUID pk) sent
    # against this store's int pk must not reach the database as
    # `integer < uuid` — it should be treated as a plain invalid cursor.
    _make(store, user_id="u1")
    crafted = base64.urlsafe_b64encode(
        json.dumps(
            {
                "o": "updated_at_desc",
                "v": NOW.isoformat(),
                "id": {"t": "uuid", "v": str(uuid.uuid4())},
            }
        ).encode()
    ).decode()

    with pytest.raises(InvalidCursorError):
        store.list_for_user("u1", now=NOW, cursor=crafted)


def test_crafted_cursor_int_id_against_uuid_pk_raises_invalid_cursor(engine):
    # The reverse mismatch: a plain int id sent against a UUID pk must not
    # reach the database as `uuid < integer`.
    store = UuidSessionStore(session_factory=lambda: Session(engine))
    store.create(
        token_hash="abc",
        user_id="u1",
        created_at=NOW,
        updated_at=NOW,
        expires_at=NOW + timedelta(days=1),
    )
    crafted = base64.urlsafe_b64encode(
        json.dumps({"o": "updated_at_desc", "v": NOW.isoformat(), "id": 1}).encode()
    ).decode()

    with pytest.raises(InvalidCursorError):
        store.list_for_user("u1", now=NOW, cursor=crafted)


def test_crafted_cursor_out_of_range_id_raises_invalid_cursor(store):
    _make(store, user_id="u1")
    crafted = base64.urlsafe_b64encode(
        json.dumps(
            {"o": "updated_at_desc", "v": NOW.isoformat(), "id": 10**100}
        ).encode()
    ).decode()

    with pytest.raises(InvalidCursorError):
        store.list_for_user("u1", now=NOW, cursor=crafted)


def test_model_passed_to_constructor(engine):
    # No subclass needed: the model can be given directly to the constructor.
    store = SQLModelSessionStorage(UserSession, session_factory=lambda: Session(engine))

    record = store.create(
        token_hash="abc",
        user_id="u1",
        created_at=NOW,
        updated_at=NOW,
        expires_at=NOW + timedelta(days=1),
    )

    assert record.id is not None
    assert store.get(token_hash="abc", now=NOW) is not None


def test_missing_session_model_raises_at_construction(engine):
    class NoModel(SQLModelSessionStorage):
        pass

    with pytest.raises(TypeError, match="SessionModel"):
        NoModel(session_factory=lambda: Session(engine))


def test_constructor_without_model_mentions_both_options(engine):
    with pytest.raises(TypeError, match="pass it to the constructor"):
        SQLModelSessionStorage(session_factory=lambda: Session(engine))


def test_session_base_without_a_table_is_rejected(engine):
    with pytest.raises(TypeError, match="must be a SQLModel table model"):
        SQLModelSessionStorage(SQLModelSession, session_factory=lambda: Session(engine))


def test_session_model_requires_application_owner_column(engine):
    class MissingSessionOwner(SQLModelSession, table=True):
        id: int | None = Field(default=None, primary_key=True)

    with pytest.raises(TypeError, match="user_id.*mapped column"):
        SQLModelSessionStorage(
            MissingSessionOwner, session_factory=lambda: Session(engine)
        )


def test_string_user_ids_coerced_to_int_column(engine):
    # Cross-Auth passes user ids to the session layer as strings; an integer
    # user_id column (e.g. a foreign key to an int user PK) must still work
    # across create, list, and revoke.
    store = IntUserIdSessionStore(session_factory=lambda: Session(engine))
    record = store.create(
        token_hash="abc",
        user_id="7",
        created_at=NOW,
        updated_at=NOW,
        expires_at=NOW + timedelta(days=1),
    )

    assert record.user_id == 7

    listed = store.list_for_user("7", now=NOW)
    assert [r.id for r in listed.records] == [record.id]

    assert store.revoke_all_for_user("7", revoked_at=NOW) == 1


def test_non_callable_session_factory_raises():
    with pytest.raises(TypeError, match="session_factory"):
        SessionStore(session_factory=cast(Any, None))


def test_list_status_filter_at_exact_expiry_boundary(store):
    # Matches cross_auth.session_status: active up to and including expiry, so a
    # session expiring exactly at `now` is active, not expired.
    boundary = _make(store, token_hash="boundary", user_id="u1", expires=NOW)
    expired = _make(
        store, token_hash="expired", user_id="u1", expires=NOW - timedelta(seconds=1)
    )

    active = [r.id for r in store.list_for_user("u1", now=NOW, status="active").records]
    gone = [r.id for r in store.list_for_user("u1", now=NOW, status="expired").records]

    assert boundary.id in active and boundary.id not in gone
    assert expired.id in gone and expired.id not in active


def test_renamed_columns_full_lifecycle(engine):
    # Every operation must work when the model maps its attributes to differently
    # named database columns — columns are resolved by attribute, not DB name.
    store = RenamedColumnSessionStore(session_factory=lambda: Session(engine))
    record = store.create(
        token_hash="rt",
        user_id="u1",
        created_at=NOW,
        updated_at=NOW,
        expires_at=NOW + timedelta(days=1),
        last_active_at=NOW,
    )

    assert record.id is not None
    assert record.created_at == NOW
    assert store.get(token_hash="rt", now=NOW) is not None
    assert store.get_any(record.id) is not None
    assert store.get_any(str(record.id)) is not None  # _coerce_id on the renamed pk
    assert [r.id for r in store.list_for_user("u1", now=NOW).records] == [record.id]

    refreshed = store.refresh(
        record.id,
        updated_at=NOW + timedelta(hours=1),
        expires_at=NOW + timedelta(days=2),
    )
    assert refreshed is not None and refreshed.updated_at == NOW + timedelta(hours=1)

    store.revoke(record.id, revoked_at=NOW)
    assert store.get(token_hash="rt", now=NOW) is None


def test_timezone_aware_columns_round_trip(engine):
    # The documented timestamptz alternative to naive columns: aware values must
    # survive the round trip with their tzinfo intact.
    store = TzAwareSessionStore(session_factory=lambda: Session(engine))
    expires = NOW + timedelta(days=1)
    store.create(
        token_hash="tz",
        user_id="u1",
        created_at=NOW,
        updated_at=NOW,
        expires_at=expires,
        last_active_at=NOW,
    )

    fetched = store.get(token_hash="tz", now=NOW)

    assert fetched is not None
    assert fetched.created_at == NOW
    assert fetched.expires_at == expires
    assert fetched.created_at.tzinfo is not None


def test_login_method_is_stored_and_read_back(store):
    session_storage = cast(SessionStorage, store)

    token, created = create_session("u1", session_storage, login_method="github")

    assert created.login_method == "github"
    session = get_session(token, session_storage)
    assert session is not None
    assert session.login_method == "github"
    (listed,) = store.list_for_user("u1", now=datetime.now(tz=timezone.utc)).records
    assert listed.login_method == "github"
