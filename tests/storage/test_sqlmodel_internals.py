"""Unit tests for the column-resolution helpers.

These guard the rule that columns are resolved by their Python attribute name,
not their database column name — the two diverge when a model renames a column,
and getting it wrong silently reintroduces the timezone shift and id-coercion
that the adapter exists to prevent.
"""

import uuid
from datetime import datetime, timezone

from cross_auth.storage.sqlmodel import _NO_MATCH, _bind_datetime, _coerce_id, _column

from .models import (
    RenamedColumnSession,
    TzAwareUserSession,
    UserSession,
    UuidUserSession,
)

AWARE = datetime(2026, 6, 6, 12, 0, 0, tzinfo=timezone.utc)


def test_column_resolves_renamed_column_by_attribute():
    column = _column(RenamedColumnSession, "created_at")

    assert column is not None
    assert column.name == "created_ts"  # the database name differs


def test_column_returns_none_for_non_column_attribute():
    assert _column(UserSession, "status") is None  # a plain property
    assert _column(UserSession, "does_not_exist") is None


def test_bind_datetime_strips_tz_for_naive_column():
    bound = _bind_datetime(UserSession, "created_at", AWARE)

    assert bound is not None
    assert bound.tzinfo is None


def test_bind_datetime_keeps_tz_for_aware_column():
    bound = _bind_datetime(TzAwareUserSession, "created_at", AWARE)

    assert bound is not None
    assert bound.tzinfo is not None


def test_bind_datetime_strips_tz_for_renamed_naive_column():
    # Regression: a renamed naive column must still be detected as naive and
    # have its tzinfo stripped, otherwise PostgreSQL shifts the stored instant.
    bound = _bind_datetime(RenamedColumnSession, "created_at", AWARE)

    assert bound is not None
    assert bound.tzinfo is None


def test_coerce_id_coerces_string_for_renamed_int_pk():
    # Regression: the renamed integer primary key must still be coerced from a
    # string, and an uncoercible value must map to _NO_MATCH (not pass through).
    assert _coerce_id(RenamedColumnSession, "id", "5") == 5
    assert _coerce_id(RenamedColumnSession, "id", "abc") is _NO_MATCH


def test_coerce_id_rejects_uuid_against_int_pk():
    # A uuid.UUID id (e.g. decoded from a crafted pagination cursor) against
    # an int column would otherwise reach the database as `integer < uuid`,
    # raising ProgrammingError on PostgreSQL.
    assert _coerce_id(UserSession, "id", uuid.uuid4()) is _NO_MATCH


def test_coerce_id_rejects_int_against_uuid_pk():
    # An int id against a UUID column would otherwise reach the database as
    # `uuid < integer`, raising ProgrammingError on PostgreSQL.
    assert _coerce_id(UuidUserSession, "id", 5) is _NO_MATCH


def test_coerce_id_rejects_out_of_range_int():
    # Passed through, these raise DataError (PostgreSQL int4) or
    # OverflowError (SQLite) at the driver instead of matching no row.
    assert _coerce_id(UserSession, "id", 2**31) is _NO_MATCH
    assert _coerce_id(UserSession, "id", 10**100) is _NO_MATCH
    assert _coerce_id(UserSession, "id", "99999999999") is _NO_MATCH


def test_coerce_id_passes_through_in_range_int():
    assert _coerce_id(UserSession, "id", 2**31 - 1) == 2**31 - 1
    assert _coerce_id(UserSession, "id", -(2**31)) == -(2**31)
