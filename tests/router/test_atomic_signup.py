"""Signup publishes creation events only after both records are persisted."""

from dataclasses import replace

import pytest
import respx

from cross_auth.exceptions import CrossAuthException

from .conftest import mock_token_and_userinfo, start_provider_auth


@pytest.mark.parametrize(
    "failure", ["before_identity", "identity_storage", "ownership"]
)
@respx.mock
def test_signup_failure_rolls_back_user_and_emits_no_after_hooks(
    auth, client, accounts_storage, monkeypatch, failure
):
    events = []

    @auth.before("user.create")
    def before_user(event):
        events.append("before_user")
        return event

    @auth.before("social_account.create")
    def before_identity(event):
        events.append("before_identity")
        assert event.user_id == "new-identity"
        if failure == "before_identity":
            raise CrossAuthException("access_denied")
        if failure == "ownership":
            return replace(event, user_id="test")
        return event

    @auth.after("user.create")
    def after_user(event):
        events.append("after_user")

    @auth.after("social_account.create")
    def after_identity(event):
        events.append("after_identity")

    if failure == "identity_storage":

        def fail_create(**kwargs):
            raise CrossAuthException("account_already_linked")

        monkeypatch.setattr(accounts_storage, "create_social_account", fail_create)

    mock_token_and_userinfo(email="new@example.com", provider_user_id="new-identity")
    _, state = start_provider_auth(client, "/fake/login")

    if failure == "ownership":
        with pytest.raises(ValueError, match="must belong to the new user"):
            client.get("/fake/callback", params={"code": "code", "state": state})
    else:
        response = client.get("/fake/callback", params={"code": "code", "state": state})
        assert response.status_code == 400

    assert list(accounts_storage.data) == ["test"]
    assert accounts_storage.data["test"].social_accounts == []
    assert events == ["before_user", "before_identity"]


@respx.mock
def test_after_user_hook_sees_committed_identity_and_failure_does_not_undo_signup(
    auth, client, accounts_storage
):
    events = []

    @auth.before("social_account.create")
    def before_identity(event):
        events.append("before_identity")
        return event

    @auth.after("user.create")
    def after_user(event):
        events.append("after_user")
        account = accounts_storage.find_social_account(
            provider="fake", provider_user_id="new-identity", user_id=event.user.id
        )
        assert account is not None
        raise RuntimeError("external service failed")

    @auth.after("social_account.create")
    def after_identity(event):
        events.append("after_identity")

    mock_token_and_userinfo(email="new@example.com", provider_user_id="new-identity")
    _, state = start_provider_auth(client, "/fake/login")

    with pytest.raises(RuntimeError, match="external service failed"):
        client.get("/fake/callback", params={"code": "code", "state": state})

    user = accounts_storage.find_user_by_email("new@example.com")
    assert user is not None
    assert len(user.social_accounts) == 1
    assert events == ["before_identity", "after_user"]
