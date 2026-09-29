import pytest

from cross_auth._context import Context


def test_create_session_rejects_without_session_storage(
    secondary_storage, accounts_storage
):
    context = Context(
        secondary_storage=secondary_storage,
        accounts_storage=accounts_storage,
        get_user_from_request=lambda _: None,
    )

    with pytest.raises(RuntimeError, match="Session flow not configured"):
        context.create_session("test")


def test_cookie_auth_enabled_reflects_config(
    secondary_storage, accounts_storage, session_storage
):
    enabled = Context(
        secondary_storage=secondary_storage,
        accounts_storage=accounts_storage,
        session_storage=session_storage,
        get_user_from_request=lambda _: None,
        config={"session": {"cookies": {"auth": True}}},
    )
    disabled = Context(
        secondary_storage=secondary_storage,
        accounts_storage=accounts_storage,
        session_storage=session_storage,
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
            get_user_from_request=lambda _: None,
            config={"session": {"cookies": {"auth": True}}},
        )
