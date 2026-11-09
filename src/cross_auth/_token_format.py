"""Opaque tokens that name what they are, like GitHub's ``ghp_`` tokens.

A token is ``{prefix}_{entropy}{checksum}``: 32 random base62 characters, then
the CRC32 of ``{prefix}_{entropy}`` as 6 base62 characters. The prefix lets
people and secret scanners recognize a leaked token, and the checksum lets a
server reject a mistyped or made-up one without looking it up. The checksum is
public: it says nothing about whether the token was issued.
"""

from __future__ import annotations

import hmac
import re
import secrets
import string
import zlib

# Digits, then upper case, then lower case: tokens other code already issued
# depend on this order.
_ALPHABET = string.digits + string.ascii_uppercase + string.ascii_lowercase
_ENTROPY_LENGTH = 32
_CHECKSUM_LENGTH = 6
_PREFIX = re.compile(r"[a-z][a-z0-9]{0,15}")
_BODY = re.compile(rf"[0-9A-Za-z]{{{_ENTROPY_LENGTH + _CHECKSUM_LENGTH}}}")


def validate_prefix(prefix: str) -> None:
    """Raise ``ValueError`` unless ``prefix`` is 1 to 16 lowercase letters and
    digits starting with a letter."""
    if not isinstance(prefix, str) or _PREFIX.fullmatch(prefix) is None:
        raise ValueError(
            f"Invalid token prefix {prefix!r}: use 1 to 16 lowercase letters "
            "and digits, starting with a letter"
        )


def generate_token(prefix: str) -> str:
    validate_prefix(prefix)
    entropy = "".join(secrets.choice(_ALPHABET) for _ in range(_ENTROPY_LENGTH))
    head = f"{prefix}_{entropy}"
    return head + _checksum(head)


def is_well_formed(token: str, prefix: str) -> bool:
    """Whether ``token`` has the shape and checksum of a ``prefix`` token.

    This checks the format only; it does not say the token was ever issued.
    """
    marker = f"{prefix}_"
    if not token.startswith(marker):
        return False
    body = token[len(marker) :]
    if _BODY.fullmatch(body) is None:
        return False
    head = marker + body[:_ENTROPY_LENGTH]
    return hmac.compare_digest(body[_ENTROPY_LENGTH:], _checksum(head))


def _checksum(head: str) -> str:
    value = zlib.crc32(head.encode("utf-8")) & 0xFFFFFFFF
    digits: list[str] = []
    while value:
        value, digit = divmod(value, len(_ALPHABET))
        digits.append(_ALPHABET[digit])
    return "".join(reversed(digits)).rjust(_CHECKSUM_LENGTH, "0")
