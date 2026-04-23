import pytest

from cross_auth._context import Context
from cross_auth._session import get_session


def test_is_session_enabled_false_without_session_support(context: Context):
    assert context.is_session_enabled is False
    with pytest.raises(RuntimeError, match="Session flow not configured"):
        context.create_session_cookie("test")


def test_is_session_enabled_true_with_session_support(
    secondary_storage, accounts_storage
):
    context = Context(
        secondary_storage=secondary_storage,
        accounts_storage=accounts_storage,
        create_token=lambda user_id: (user_id, 0),
        trusted_origins=[],
        get_user_from_request=lambda _: None,
        session_enabled=True,
    )

    assert context.is_session_enabled is True
    cookie = context.create_session_cookie("test-user")
    session = get_session(cookie.value, secondary_storage)
    assert session is not None
    assert session.user_id == "test-user"
