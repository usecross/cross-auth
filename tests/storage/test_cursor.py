import base64
import json
import uuid
from datetime import datetime, timezone

import pytest

from cross_auth.storage import InvalidCursorError
from cross_auth.storage._cursor import (
    _MAX_CURSOR_LENGTH,
    decode_cursor,
    encode_cursor,
)

NOW = datetime(2026, 6, 6, 12, 0, 0, tzinfo=timezone.utc)


def _craft(payload: object) -> str:
    return base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()


@pytest.mark.parametrize("row_id", [42, "row-1", "x" * 320, "🔑" * 200, uuid.uuid4()])
def test_round_trip(row_id):
    cursor = encode_cursor("updated_at_desc", NOW, row_id)

    decoded = decode_cursor(cursor)

    assert decoded.order_by == "updated_at_desc"
    assert decoded.value == NOW
    assert decoded.row_id == row_id
    assert type(decoded.row_id) is type(row_id)


def test_invalid_cursor_error_is_a_value_error():
    assert issubclass(InvalidCursorError, ValueError)


def test_invalid_cursor_error_canonical_home_is_exceptions():
    # Custom SessionStorage implementations import it from cross_auth.exceptions
    # without touching the adapter package; cross_auth.storage re-exports it.
    from cross_auth import exceptions

    assert InvalidCursorError is exceptions.InvalidCursorError


@pytest.mark.parametrize(
    "cursor",
    [
        "not base64 at all!",
        base64.urlsafe_b64encode(b"not json").decode(),
        _craft(["a", "list"]),
        _craft({"v": NOW.isoformat(), "id": 1}),  # missing order
        _craft({"o": "updated_at_desc", "id": 1}),  # missing value
        _craft({"o": "updated_at_desc", "v": "not-a-date", "id": 1}),
        _craft({"o": "updated_at_desc", "v": NOW.isoformat()}),  # missing id
        _craft({"o": "updated_at_desc", "v": NOW.isoformat(), "id": {"x": 1}}),
        _craft({"o": "updated_at_desc", "v": NOW.isoformat(), "id": None}),
        _craft({"o": "updated_at_desc", "v": NOW.isoformat(), "id": True}),
        _craft({"o": "updated_at_desc", "v": NOW.isoformat(), "id": [1]}),
        _craft({"o": "updated_at_desc", "v": NOW.isoformat(), "id": {"t": "uuid"}}),
        _craft(
            {
                "o": "updated_at_desc",
                "v": NOW.isoformat(),
                "id": {"t": "uuid", "v": "not-a-uuid"},
            }
        ),
    ],
)
def test_decode_rejects_malformed_cursors(cursor):
    with pytest.raises(InvalidCursorError):
        decode_cursor(cursor)


@pytest.mark.parametrize("character", ["x", "é", "🔑"])
def test_payload_bound_is_symmetric(character):
    # Exercise the encoded size, which includes JSON's Unicode escaping.
    row_id = character
    while True:
        try:
            cursor = encode_cursor("updated_at_desc", NOW, row_id + character)
        except ValueError:
            break
        row_id += character
    cursor = encode_cursor("updated_at_desc", NOW, row_id)
    assert len(cursor) <= _MAX_CURSOR_LENGTH
    assert decode_cursor(cursor).row_id == row_id
    with pytest.raises(ValueError, match="shorter session ID"):
        encode_cursor("updated_at_desc", NOW, row_id + character)


def test_decode_rejects_oversized_cursor():
    with pytest.raises(InvalidCursorError):
        decode_cursor("a" * (_MAX_CURSOR_LENGTH + 1))


def test_decode_rejects_deeply_nested_payload():
    # Bounded input can still exhaust the JSON decoder's recursion limit.
    crafted = base64.urlsafe_b64encode(("[" * 1500).encode()).decode()

    with pytest.raises(InvalidCursorError):
        decode_cursor(crafted)


def test_encode_rejects_unsupported_id_types():
    with pytest.raises(TypeError, match="bytes"):
        encode_cursor("updated_at_desc", NOW, b"binary-id")

    with pytest.raises(TypeError, match="bool"):
        encode_cursor("updated_at_desc", NOW, True)
