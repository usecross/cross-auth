from collections.abc import Iterator
from datetime import datetime, timezone
from typing import LiteralString, cast
from unittest.mock import Mock, patch

import bcrypt
import pytest
from cross_web import HTTPRequest, TestingHTTPRequestAdapter

from cross_auth import AccountsStorage, SessionStorage
from cross_auth._password import DUMMY_PASSWORD_HASH, _verify_password, authenticate
from cross_auth._session import (
    SessionConfig,
    clean_ip,
    clean_session_metadata,
    clean_user_agent,
    create_session,
    delete_session,
    get_current_user,
    get_session,
    make_clear_cookie,
    make_session_cookie,
    request_metadata,
)
from cross_auth._storage import User
from cross_auth._token_format import is_well_formed

TEST_PASSWORD = "password123"  # noqa: S105


@pytest.mark.parametrize(
    (
        "user_exists",
        "password_hash",
        "verification_result",
        "expected_hash",
        "expected_validity",
    ),
    [
        pytest.param(True, "real-hash", True, "real-hash", True, id="correct"),
        pytest.param(True, "real-hash", False, "real-hash", False, id="incorrect"),
        pytest.param(False, None, True, DUMMY_PASSWORD_HASH, False, id="missing-user"),
        pytest.param(True, None, True, DUMMY_PASSWORD_HASH, False, id="passwordless"),
    ],
)
def test_verify_password_once(
    user_exists: bool,
    password_hash: str | None,
    verification_result: bool,
    expected_hash: str,
    expected_validity: bool,
):
    user = cast(User, Mock(hashed_password=password_hash)) if user_exists else None

    with patch(
        "cross_auth._password._check_password",
        return_value=verification_result,
    ) as verify:
        valid = _verify_password(user, TEST_PASSWORD)

    assert valid is expected_validity
    verify.assert_called_once_with(TEST_PASSWORD, expected_hash)


def test_verify_password_uses_the_first_72_bytes_like_passlib_did():
    """Hashes made by passlib from longer passwords keep verifying."""
    password = "p" * 80
    hashed = bcrypt.hashpw(password.encode()[:72], bcrypt.gensalt(rounds=4)).decode()
    user = cast(User, Mock(hashed_password=hashed))

    assert _verify_password(user, password) is True
    assert _verify_password(user, "p" * 72) is True
    assert _verify_password(user, "p" * 71) is False


def test_verify_password_rejects_a_hash_bcrypt_cannot_read():
    foreign = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo"
    user = cast(User, Mock(hashed_password=foreign))

    assert _verify_password(user, TEST_PASSWORD) is False


def test_authenticate_success(accounts_storage: AccountsStorage):
    user = authenticate("test@example.com", TEST_PASSWORD, accounts_storage)
    assert user is not None
    assert user.email == "test@example.com"


def test_authenticate_wrong_password(accounts_storage: AccountsStorage):
    result = authenticate("test@example.com", "wrong-password", accounts_storage)
    assert result is None


def test_authenticate_nonexistent_user(accounts_storage: AccountsStorage):
    result = authenticate("nonexistent@example.com", "any-password", accounts_storage)
    assert result is None


def test_create_session(session_storage: SessionStorage):
    session_id, session_record = create_session("test-user", session_storage)

    assert isinstance(session_id, str)
    assert len(session_id) > 0
    assert session_record.user_id == "test-user"
    assert session_record.created_at is not None
    assert session_record.expires_at is not None
    assert session_record.expires_at > session_record.created_at

    stored = session_storage.get_any(session_record.id)
    assert stored is session_record


def test_create_session_without_token_prefix_uses_token_urlsafe(
    session_storage: SessionStorage,
):
    with patch(
        "cross_auth._session.secrets.token_urlsafe", return_value="opaque-token"
    ) as token_urlsafe:
        session_token, session_record = create_session("test-user", session_storage)

    token_urlsafe.assert_called_once_with(32)
    assert session_token == "opaque-token"
    retrieved = get_session("opaque-token", session_storage)
    assert retrieved is not None
    assert retrieved.id == session_record.id


def test_create_session_with_token_prefix(session_storage: SessionStorage):
    session_token, session_record = create_session(
        "test-user", session_storage, token_prefix="app"
    )

    assert session_token.startswith("app_")
    assert is_well_formed(session_token, "app")
    retrieved = get_session(session_token, session_storage, {"token_prefix": "app"})
    assert retrieved is not None
    assert retrieved.id == session_record.id


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_0) Chrome/130.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_0) Chrome/130.0",
        ),
        (
            "  Mozilla/5.0\x00\x1b[31m (X11)\r\n\tFirefox  ",
            "Mozilla/5.0 [31m (X11) Firefox",
        ),
        ("Bad\u2028line\u200bbreaks", "Bad line breaks"),
        ("Chrome\u202eexe.fdp", "Chrome exe.fdp"),
        ("x" * 513, "x" * 512),
        (" " * 1024 + "Firefox", "Firefox"),
        ("Firefox" + "\x00 " * 1024 + "Browser", "Firefox Browser"),
        ("x" * 511 + "\nFirefox", "x" * 511),
        ("x" * 510 + "\nFirefox", "x" * 510 + " F"),
        ("\x00\r\n ", None),
        ("", None),
        (None, None),
    ],
)
def test_user_agent_is_sanitized(value: str | None, expected: str | None) -> None:
    assert clean_user_agent(value) == expected


def test_user_agent_cleaning_stops_at_the_output_limit() -> None:
    class GuardedText(str):
        def __iter__(self) -> Iterator[LiteralString]:
            for index in range(len(self)):
                assert index < 512, "Cleaner read beyond the output limit"
                yield "x"

    assert clean_user_agent(GuardedText("x" * 1_000_000)) == "x" * 512


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("198.51.100.7", "198.51.100.7"),
        ("2001:DB8:0:0::1", "2001:db8::1"),
        ("::ffff:198.51.100.7", "198.51.100.7"),
        ("fe80::1%eth0", "fe80::1"),
        ("fe80::1%3", "fe80::1"),
        ("::ffff:198.51.100.7%eth0", "198.51.100.7"),
        ("198.51.100.7%invalid", None),
        ("198.51.100.7%invalid, 10.0.0.1", None),
        ("fe80::1%", None),
        ("fe80::1%eth0%extra", None),
        ("fe80::1%eth0, 10.0.0.1", None),
        ("fe80::1%eth0,10.0.0.1", None),
        ("fe80::1%eth 0", None),
        ("fe80::1%eth0\x00", None),
        ("fe80::1%eth0/64", None),
        (" 198.51.100.7 ", "198.51.100.7"),
        ("198.51.100.7, 10.0.0.1", None),
        ("unknown", None),
        ("", None),
        (None, None),
    ],
)
def test_ip_is_normalized(value: str | None, expected: str | None) -> None:
    assert clean_ip(value) == expected


def test_session_metadata_is_cleaned() -> None:
    assert clean_session_metadata(
        {
            "client_id": " cli\n",
            "client_name": "My\x00 Laptop" + "x" * 300,
            "user_agent": "cli/2.0\r\n",
            "ip": "::ffff:203.0.113.7",
        }
    ) == {
        "client_id": "cli",
        "client_name": ("My Laptop" + "x" * 300)[:255],
        "user_agent": "cli/2.0",
        "ip": "203.0.113.7",
    }
    assert clean_session_metadata(None) == {
        "client_id": None,
        "client_name": None,
        "user_agent": None,
        "ip": None,
    }


def test_create_session_stores_cleaned_metadata(session_storage: SessionStorage):
    _, session_record = create_session(
        "test-user",
        session_storage,
        metadata={
            "client_id": "cli\x1b[2J",
            "client_name": "  ",
            "user_agent": "Mozilla/5.0\u202e (X11)",
            "ip": "203.0.113.7, 10.0.0.1",
        },
    )

    assert session_record.client_id == "cli [2J"
    assert session_record.client_name is None
    assert session_record.user_agent == "Mozilla/5.0 (X11)"
    assert session_record.ip is None


def test_create_session_can_skip_the_ip(session_storage: SessionStorage):
    _, session_record = create_session(
        "test-user",
        session_storage,
        metadata={"user_agent": "cli/3.0", "ip": "203.0.113.7"},
        store_ip=False,
    )

    assert session_record.user_agent == "cli/3.0"
    assert session_record.ip is None


@pytest.mark.parametrize(
    ("config", "expected"),
    [
        (None, {"user_agent": "cli/3.0", "ip": "203.0.113.7"}),
        ({"store_ip": True}, {"user_agent": "cli/3.0", "ip": "203.0.113.7"}),
        ({"store_ip": False}, {"user_agent": "cli/3.0"}),
    ],
)
def test_request_metadata(
    config: SessionConfig | None, expected: dict[str, str]
) -> None:
    request = HTTPRequest(
        TestingHTTPRequestAdapter(
            headers={"User-Agent": "cli/3.0"}, client_host="203.0.113.7"
        )
    )

    assert request_metadata(request, config) == expected


def test_sessions_issued_before_token_prefix_still_resolve(
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    """Setting token_prefix changes new tokens only. Lookups hash whatever
    token arrives, so sessions issued before keep working until they expire."""
    session_token, session_record = create_session("test", session_storage)
    config: SessionConfig = {"token_prefix": "app"}

    retrieved = get_session(session_token, session_storage, config)
    assert retrieved is not None
    assert retrieved.id == session_record.id

    cookie_request = _make_request({"session_id": session_token})
    bearer_request = HTTPRequest(
        TestingHTTPRequestAdapter(headers={"Authorization": f"Bearer {session_token}"})
    )
    for request in (cookie_request, bearer_request):
        user = get_current_user(request, session_storage, accounts_storage, config)
        assert user is not None
        assert user.email == "test@example.com"


def test_get_session(session_storage: SessionStorage):
    session_id, original = create_session("test-user", session_storage)

    retrieved = get_session(session_id, session_storage)
    assert retrieved is not None
    assert retrieved.user_id == "test-user"
    assert retrieved.created_at == original.created_at


def test_get_session_expired(session_storage: SessionStorage):
    session_id, session = create_session("test-user", session_storage, max_age=1)

    future = datetime(2099, 1, 1, tzinfo=timezone.utc)
    with patch("cross_auth._session.datetime") as mock_dt:
        mock_dt.now.return_value = future
        result = get_session(session_id, session_storage)

    assert result is None
    assert session_storage.get_any(session.id) is session


def test_get_session_not_found(session_storage: SessionStorage):
    result = get_session("nonexistent-id", session_storage)
    assert result is None


def test_delete_session(session_storage: SessionStorage):
    session_id, session = create_session("test-user", session_storage)

    delete_session(session_id, session_storage)

    result = get_session(session_id, session_storage)
    assert result is None
    assert session.revoked_at is not None


def test_delete_session_not_found(session_storage: SessionStorage):
    delete_session("nonexistent-id", session_storage)


def test_make_session_cookie():
    cookie = make_session_cookie("my-session-id")

    assert cookie.name == "session_id"
    assert cookie.value == "my-session-id"
    assert cookie.httponly is True
    assert cookie.secure is True
    assert cookie.samesite == "lax"
    assert cookie.path == "/"
    assert cookie.domain is None


def test_make_session_cookie_custom_config():
    config: SessionConfig = {
        "max_age": 3600,
        "cookies": {
            "name": "my_session",
            "secure": False,
            "httponly": False,
            "samesite": "strict",
            "path": "/app",
            "domain": "example.com",
        },
    }
    cookie = make_session_cookie("my-session-id", config)

    assert cookie.name == "my_session"
    assert cookie.value == "my-session-id"
    assert cookie.httponly is False
    assert cookie.secure is False
    assert cookie.samesite == "strict"
    assert cookie.path == "/app"
    assert cookie.domain == "example.com"
    assert cookie.max_age == 3600


def test_make_clear_cookie():
    config: SessionConfig = {
        "cookies": {
            "name": "my_session",
            "path": "/app",
            "domain": "example.com",
        },
    }
    cookie = make_clear_cookie(config)

    assert cookie.name == "my_session"
    assert cookie.value == ""
    assert cookie.max_age == 0
    assert cookie.path == "/app"
    assert cookie.domain == "example.com"


def _make_request(cookies: dict[str, str] | None = None) -> HTTPRequest:
    return HTTPRequest(TestingHTTPRequestAdapter(cookies=cookies))


def test_get_current_user(
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    session_id, _ = create_session("test", session_storage)
    request = _make_request({"session_id": session_id})

    user = get_current_user(request, session_storage, accounts_storage)

    assert user is not None
    assert user.email == "test@example.com"


def test_get_current_user_no_cookie(
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    request = _make_request()

    result = get_current_user(request, session_storage, accounts_storage)

    assert result is None


def test_get_current_user_invalid_session(
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    request = _make_request({"session_id": "nonexistent"})

    result = get_current_user(request, session_storage, accounts_storage)

    assert result is None


def test_get_current_user_expired_session(
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    session_id, _ = create_session("test", session_storage, max_age=1)
    request = _make_request({"session_id": session_id})

    future = datetime(2099, 1, 1, tzinfo=timezone.utc)
    with patch("cross_auth._session.datetime") as mock_dt:
        mock_dt.now.return_value = future
        result = get_current_user(request, session_storage, accounts_storage)

    assert result is None


def test_get_current_user_user_not_found(
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    session_id, _ = create_session("nonexistent-user", session_storage)
    request = _make_request({"session_id": session_id})

    result = get_current_user(request, session_storage, accounts_storage)

    assert result is None


def test_get_current_user_custom_cookie_name(
    accounts_storage: AccountsStorage,
    session_storage: SessionStorage,
):
    session_id, _ = create_session("test", session_storage)
    config: SessionConfig = {"cookies": {"name": "my_session"}}
    request = _make_request({"my_session": session_id})

    user = get_current_user(request, session_storage, accounts_storage, config)

    assert user is not None
    assert user.email == "test@example.com"
