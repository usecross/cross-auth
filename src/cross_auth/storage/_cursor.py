import base64
import binascii
import json
import uuid
from dataclasses import dataclass
from datetime import datetime

from cross_auth.exceptions import InvalidCursorError


@dataclass(frozen=True)
class Cursor:
    order_by: str
    value: datetime
    row_id: object


def encode_cursor(order_by: str, order_value: datetime, row_id: object) -> str:
    payload = {
        "o": order_by,
        "v": order_value.isoformat(),
        "id": _serialize_cursor_id(row_id),
    }
    raw = json.dumps(payload, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode()


# Legitimate cursors are ~100-200 bytes; a much longer one is crafted. Reject
# it before decoding — a deeply nested payload (e.g. `"["*1500`) makes
# json.loads raise RecursionError instead of a clean parse failure.
_MAX_CURSOR_LENGTH = 512


def decode_cursor(cursor: str) -> Cursor:
    if len(cursor) > _MAX_CURSOR_LENGTH:
        raise InvalidCursorError("Invalid session pagination cursor")
    try:
        raw = base64.urlsafe_b64decode(cursor.encode())
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise InvalidCursorError("Invalid session pagination cursor")
        order_by = payload["o"]
        value = payload["v"]
        if not isinstance(order_by, str) or not isinstance(value, str):
            raise InvalidCursorError("Invalid session pagination cursor")
        return Cursor(
            order_by=order_by,
            value=datetime.fromisoformat(value),
            row_id=_deserialize_cursor_id(payload["id"]),
        )
    except (
        ValueError,
        KeyError,
        TypeError,
        binascii.Error,
        RecursionError,
    ) as exc:
        raise InvalidCursorError("Invalid session pagination cursor") from exc


def _serialize_cursor_id(row_id: object) -> object:
    if isinstance(row_id, uuid.UUID):
        return {"t": "uuid", "v": str(row_id)}
    # bool is excluded explicitly: it is an int subclass but never a valid id.
    if isinstance(row_id, bool) or not isinstance(row_id, (int, str)):
        raise TypeError(
            f"Unsupported session id type for cursor pagination: "
            f"{type(row_id).__name__!r} (supported: int, str, uuid.UUID)"
        )
    return row_id


def _deserialize_cursor_id(value: object) -> object:
    match value:
        case {"t": "uuid", "v": str(raw)}:
            return uuid.UUID(raw)
        case bool():
            raise InvalidCursorError("Invalid session pagination cursor")
        case int() | str():
            return value
    raise InvalidCursorError("Invalid session pagination cursor")
