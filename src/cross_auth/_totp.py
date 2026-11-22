"""Time-based one-time passwords (RFC 6238) with HMAC-SHA1 and 6 digits.

These are the settings every authenticator app understands, so they are not
configurable: secrets imported from another provider must use them too.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
from datetime import datetime
from urllib.parse import quote, urlencode

PERIOD = 30
DIGITS = 6
_SECRET_BYTES = 20


def generate_secret() -> str:
    """Return a new random secret, base32 without padding, as apps expect."""
    return base64.b32encode(secrets.token_bytes(_SECRET_BYTES)).decode().rstrip("=")


def _key(secret: str) -> bytes:
    normalized = secret.replace(" ", "").upper()
    return base64.b32decode(normalized + "=" * (-len(normalized) % 8))


def time_step(now: datetime) -> int:
    return int(now.timestamp()) // PERIOD


def code_at(secret: str, step: int) -> str:
    digest = hmac.new(_key(secret), struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10**DIGITS).zfill(DIGITS)


def matching_step(
    secret: str, code: str, *, now: datetime, tolerance: int
) -> int | None:
    """Return the time step ``code`` belongs to, within ``tolerance`` steps of now.

    Every candidate is compared, in constant time, so the answer's timing does
    not say which step matched.
    """
    code = code.replace(" ", "")
    if len(code) != DIGITS or not code.isdigit():
        return None
    current = time_step(now)
    found = None
    for step in range(current - tolerance, current + tolerance + 1):
        if hmac.compare_digest(code_at(secret, step), code) and found is None:
            found = step
    return found


def provisioning_uri(secret: str, *, issuer: str, account: str) -> str:
    """The ``otpauth://`` URI that authenticator apps read from a QR code."""
    label = quote(f"{issuer}:{account}", safe=":@")
    query = urlencode(
        {
            "secret": secret,
            "issuer": issuer,
            "algorithm": "SHA1",
            "digits": DIGITS,
            "period": PERIOD,
        }
    )
    return f"otpauth://totp/{label}?{query}"
