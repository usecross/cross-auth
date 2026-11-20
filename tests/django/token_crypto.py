"""Stand-ins for an application's token encryption, for the tests."""

PREFIX = "enc:"


def encrypt(value: str) -> str:
    return PREFIX + value[::-1]


def decrypt(value: str) -> str | None:
    # Like a real cipher after a key change: text it did not write is unreadable.
    if not value.startswith(PREFIX):
        return None
    return value.removeprefix(PREFIX)[::-1]


def not_a_function() -> None: ...


NOT_CALLABLE = "text"
