import httpx
import pytest
import respx

from cross_auth.models.oauth_token_response import TokenResponse
from cross_auth.social_providers.github import GitHubProvider
from cross_auth.social_providers.oauth import OAuth2Exception


@pytest.mark.parametrize("endpoint", ["profile", "emails"])
@pytest.mark.parametrize("failure", ["status", "transport", "json"])
@respx.mock
def test_provider_profile_failures_do_not_log_response_values(
    endpoint, failure, caplog, context
):
    marker = "private-profile-marker"
    provider = GitHubProvider(
        client_id="client",
        client_secret="secret",
        api_base_url=f"https://provider.example/{marker}",
    )
    profile = {"id": 1, "login": "octocat", "email": "public@example.com"}
    user_route = respx.get(provider.user_info_endpoint).respond(200, json=profile)
    failed = (
        user_route if endpoint == "profile" else respx.get(provider.emails_endpoint)
    )
    if failure == "status":
        failed.respond(503, text=marker)
    elif failure == "transport":
        failed.mock(side_effect=httpx.ReadTimeout(marker))
    else:
        failed.respond(200, text=marker)
    response = TokenResponse(token_type="Bearer", access_token=marker, scope=marker)

    if endpoint == "profile":
        with pytest.raises(OAuth2Exception) as error:
            provider.fetch_user_info(response, context)
        assert error.value.error == "server_error"
        assert error.value.error_description == "Failed to fetch user info"
    else:
        info = provider.fetch_user_info(response, context)
        assert info["email"] == "public@example.com"
        assert info["name"] == "octocat"

    assert len(caplog.records) == 1
    record = caplog.records[0]
    assert record.__dict__["oauth_provider"] == "github"
    assert marker not in str(record.__dict__)
    assert marker not in caplog.text
    if failure == "status":
        assert record.__dict__["oauth_status_code"] == 503
    else:
        assert "error_type=" in record.getMessage()
