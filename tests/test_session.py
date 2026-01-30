from cross_auth._session import (
    SessionConfig,
    authenticate,
    create_session,
    delete_session,
    get_session,
    make_clear_cookie,
    make_session_cookie,
)
from cross_auth._storage import AccountsStorage, SecondaryStorage

TEST_PASSWORD = "password123"


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


def test_create_session(secondary_storage: SecondaryStorage):
    session_id, session_data = create_session("test-user", secondary_storage)

    assert isinstance(session_id, str)
    assert len(session_id) > 0
    assert session_data.user_id == "test-user"
    assert session_data.created_at is not None

    raw = secondary_storage.get(f"session:{session_id}")
    assert raw is not None


def test_get_session(secondary_storage: SecondaryStorage):
    session_id, original = create_session("test-user", secondary_storage)

    retrieved = get_session(session_id, secondary_storage)
    assert retrieved is not None
    assert retrieved.user_id == "test-user"
    assert retrieved.created_at == original.created_at


def test_get_session_not_found(secondary_storage: SecondaryStorage):
    result = get_session("nonexistent-id", secondary_storage)
    assert result is None


def test_delete_session(secondary_storage: SecondaryStorage):
    session_id, _ = create_session("test-user", secondary_storage)

    delete_session(session_id, secondary_storage)

    result = get_session(session_id, secondary_storage)
    assert result is None


def test_delete_session_not_found(secondary_storage: SecondaryStorage):
    delete_session("nonexistent-id", secondary_storage)


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
        "cookie_name": "my_session",
        "max_age": 3600,
        "secure": False,
        "httponly": False,
        "samesite": "strict",
        "path": "/app",
        "domain": "example.com",
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
        "cookie_name": "my_session",
        "path": "/app",
        "domain": "example.com",
    }
    cookie = make_clear_cookie(config)

    assert cookie.name == "my_session"
    assert cookie.value == ""
    assert cookie.max_age == 0
    assert cookie.path == "/app"
    assert cookie.domain == "example.com"
