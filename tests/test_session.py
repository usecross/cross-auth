from datetime import datetime, timezone
from unittest.mock import patch

from cross_web import HTTPRequest, TestingHTTPRequestAdapter

from cross_auth import AccountsStorage, SessionStorage
from cross_auth._password import authenticate
from cross_auth._session import (
    SessionConfig,
    create_session,
    delete_session,
    get_current_user,
    get_session,
    make_clear_cookie,
    make_session_cookie,
)

TEST_PASSWORD = "password123"  # noqa: S105


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
