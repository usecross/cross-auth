import pytest

from cross_auth._context import Context
from cross_auth._session import get_session


def test_create_session_cookie_rejects_without_session_storage(
    secondary_storage, accounts_storage
):
    context = Context(
        secondary_storage=secondary_storage,
        accounts_storage=accounts_storage,
        trusted_origins=[],
        get_user_from_request=lambda _: None,
    )

    with pytest.raises(RuntimeError, match="Session flow not configured"):
        context.create_session_cookie("test")


def test_create_session_cookie_uses_session_storage(
    secondary_storage, accounts_storage, session_storage
):
    context = Context(
        secondary_storage=secondary_storage,
        accounts_storage=accounts_storage,
        session_storage=session_storage,
        trusted_origins=[],
        get_user_from_request=lambda _: None,
    )

    cookie = context.create_session_cookie("test-user")
    session = get_session(cookie.value, session_storage)
    assert session is not None
    assert session.user_id == "test-user"


def test_cookie_auth_enabled_reflects_config(
    secondary_storage, accounts_storage, session_storage
):
    enabled = Context(
        secondary_storage=secondary_storage,
        accounts_storage=accounts_storage,
        session_storage=session_storage,
        trusted_origins=[],
        get_user_from_request=lambda _: None,
        config={"session": {"cookies": {"auth": True}}},
    )
    disabled = Context(
        secondary_storage=secondary_storage,
        accounts_storage=accounts_storage,
        session_storage=session_storage,
        trusted_origins=[],
        get_user_from_request=lambda _: None,
    )

    assert enabled.cookie_auth_enabled is True
    assert disabled.cookie_auth_enabled is False


def test_cookie_auth_without_session_storage_raises(
    secondary_storage, accounts_storage
):
    with pytest.raises(ValueError, match="cookies"):
        Context(
            secondary_storage=secondary_storage,
            accounts_storage=accounts_storage,
            trusted_origins=[],
            get_user_from_request=lambda _: None,
            config={"session": {"cookies": {"auth": True}}},
        )
