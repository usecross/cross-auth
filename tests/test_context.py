from datetime import datetime, timezone

import pytest
from cross_web import HTTPRequest, TestingHTTPRequestAdapter

from cross_auth._context import Context
from cross_auth._session import SessionConfig, create_session
from cross_auth._token_format import generate_token, is_well_formed
from cross_auth._tokens import TokenIssueRequest


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


def _context_with_session(
    secondary_storage, accounts_storage, session_storage, session: SessionConfig
) -> Context:
    return Context(
        secondary_storage=secondary_storage,
        accounts_storage=accounts_storage,
        session_storage=session_storage,
        get_user_from_request=lambda _: None,
        config={"session": session},
    )


def test_create_session_uses_token_prefix(
    secondary_storage, accounts_storage, session_storage
):
    context = _context_with_session(
        secondary_storage, accounts_storage, session_storage, {"token_prefix": "app"}
    )

    session_token, _ = context.create_session("test")

    assert is_well_formed(session_token, "app")


def test_token_endpoint_session_uses_token_prefix(
    secondary_storage, accounts_storage, session_storage
):
    context = _context_with_session(
        secondary_storage, accounts_storage, session_storage, {"token_prefix": "app"}
    )

    session_token, _ = context.issue_token(
        TokenIssueRequest(
            user_id="test",
            client_id="test",
            grant_type="authorization_code",
            scope=None,
            http_request=HTTPRequest(TestingHTTPRequestAdapter()),
        )
    )

    assert is_well_formed(session_token, "app")


@pytest.mark.parametrize("prefix", ["", "App", "my_app", "1app", "a" * 17])
def test_invalid_token_prefix_raises_at_construction(
    secondary_storage, accounts_storage, session_storage, prefix
):
    with pytest.raises(ValueError, match="Invalid token prefix"):
        _context_with_session(
            secondary_storage,
            accounts_storage,
            session_storage,
            {"token_prefix": prefix},
        )


def test_identify_token(secondary_storage, accounts_storage, session_storage):
    context = _context_with_session(
        secondary_storage, accounts_storage, session_storage, {"token_prefix": "app"}
    )
    session_token, _ = context.create_session("test")
    tampered = session_token[:-1] + ("0" if session_token[-1] != "0" else "1")
    unprefixed, _ = create_session("test", session_storage)

    assert context.identify_token(session_token) == "session"
    assert context.identify_token(tampered) is None
    assert context.identify_token(unprefixed) is None
    assert context.identify_token("fcd_0123456789ABCDEFGHIJKLMNOPQRSTUV2ltEVI") is None


def test_identify_token_without_token_prefix(
    secondary_storage, accounts_storage, session_storage
):
    context = _context_with_session(
        secondary_storage, accounts_storage, session_storage, {}
    )
    session_token, _ = context.create_session("test")

    assert context.identify_token(session_token) is None
    assert context.identify_token(generate_token("app")) is None


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


def test_authenticate_session_token_returns_session_and_user(context):
    token, record = context.create_session("test")

    result = context.authenticate_session_token(token)

    assert result is not None
    assert result.session.id == record.id
    assert result.user.id == "test"


def test_authenticate_session_token_rejects_unknown_and_revoked_tokens(
    context, session_storage
):
    token, record = context.create_session("test")
    session_storage.revoke(record.id, revoked_at=datetime.now(tz=timezone.utc))

    assert context.authenticate_session_token(token) is None
    assert context.authenticate_session_token("unknown") is None


def test_authenticate_session_token_rejects_a_session_without_its_user(context):
    token, _ = context.create_session("missing")

    assert context.authenticate_session_token(token) is None


def test_authenticate_session_token_needs_storages_that_take_a_db_session(context):
    token, _ = context.create_session("test")

    with pytest.raises(TypeError, match="with_read_session"):
        context.authenticate_session_token(token, db_session=object())


def test_authenticate_session_token_rejects_without_session_storage(
    secondary_storage, accounts_storage
):
    context = Context(
        secondary_storage=secondary_storage,
        accounts_storage=accounts_storage,
        get_user_from_request=lambda _: None,
    )

    with pytest.raises(RuntimeError, match="Session flow not configured"):
        context.authenticate_session_token("token")
