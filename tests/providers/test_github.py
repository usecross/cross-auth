import pytest
import respx

from cross_auth.social_providers.github import GitHubProvider

pytestmark = pytest.mark.asyncio


@pytest.fixture
def github_provider() -> GitHubProvider:
    return GitHubProvider(
        client_id="test_client_id", client_secret="test_client_secret"
    )


@pytest.fixture
def mock_user_info() -> dict:
    return {
        "login": "octocat",
        "id": 1,
        "node_id": "MDQ6VXNlcjE=",
        "avatar_url": "https://github.com/images/error/octocat_happy.gif",
        "gravatar_id": "41d064eb2195891e12d0413f63227ea7",
        "url": "https://api.github.com/users/octocat",
        "html_url": "https://github.com/octocat",
        "followers_url": "https://api.github.com/users/octocat/followers",
        "following_url": "https://api.github.com/users/octocat/following{/other_user}",
        "gists_url": "https://api.github.com/users/octocat/gists{/gist_id}",
        "starred_url": "https://api.github.com/users/octocat/starred{/owner}{/repo}",
        "subscriptions_url": "https://api.github.com/users/octocat/subscriptions",
        "organizations_url": "https://api.github.com/users/octocat/orgs",
        "repos_url": "https://api.github.com/users/octocat/repos",
        "events_url": "https://api.github.com/users/octocat/events{/privacy}",
        "received_events_url": "https://api.github.com/users/octocat/received_events",
        "type": "User",
        "site_admin": False,
        "name": "monalisa octocat",
        "company": "GitHub",
        "blog": "https://github.com/blog",
        "location": "San Francisco",
        "email": "octocat@github.com",
        "hireable": None,
        "bio": "There once was...",
        "twitter_username": "monalisa",
        "public_repos": 2,
        "public_gists": 1,
        "followers": 20,
        "following": 0,
        "created_at": "2008-01-14T04:33:35Z",
        "updated_at": "2008-01-14T04:33:35Z",
    }


@pytest.fixture
def mock_emails() -> list[dict]:
    return [
        {
            "email": "octocat@github.com",
            "verified": True,
            "primary": True,
            "visibility": "public",
        },
        {
            "email": "octocat@example.com",
            "verified": True,
            "primary": False,
            "visibility": "private",
        },
    ]


@respx.mock
async def test_fetch_user_info_with_email(
    github_provider: GitHubProvider, mock_user_info: dict, mock_emails: list[dict]
):
    # Mock the user info endpoint
    respx.get("https://api.github.com/user").mock(
        return_value=respx.MockResponse(200, json=mock_user_info)
    )

    # Mock the emails endpoint
    respx.get("https://api.github.com/user/emails").mock(
        return_value=respx.MockResponse(200, json=mock_emails)
    )

    user_info = github_provider.fetch_user_info("test_token")

    assert user_info == mock_user_info
    assert user_info["email"] == "octocat@github.com"


@respx.mock
async def test_fetch_user_info_without_email(
    github_provider: GitHubProvider, mock_user_info: dict, mock_emails: list[dict]
):
    # Remove email from user info
    mock_user_info.pop("email")

    # Mock the user info endpoint
    respx.get("https://api.github.com/user").mock(
        return_value=respx.MockResponse(200, json=mock_user_info)
    )

    # Mock the emails endpoint
    respx.get("https://api.github.com/user/emails").mock(
        return_value=respx.MockResponse(200, json=mock_emails)
    )

    user_info = github_provider.fetch_user_info("test_token")

    assert user_info["email"] == "octocat@github.com"  # Should use primary email


@respx.mock
async def test_fetch_user_info_handles_email_fetch_error(
    github_provider: GitHubProvider, mock_user_info: dict
):
    # Remove email from user info
    mock_user_info.pop("email")

    # Mock the user info endpoint
    respx.get("https://api.github.com/user").mock(
        return_value=respx.MockResponse(200, json=mock_user_info)
    )

    # Mock the emails endpoint to fail
    respx.get("https://api.github.com/user/emails").mock(
        return_value=respx.MockResponse(500, json={"message": "Internal Server Error"})
    )

    with pytest.raises(Exception):
        github_provider.fetch_user_info("test_token")


@respx.mock
async def test_fetch_user_info_handles_user_info_error(github_provider: GitHubProvider):
    # Mock the user info endpoint to fail
    respx.get("https://api.github.com/user").mock(
        return_value=respx.MockResponse(500, json={"message": "Internal Server Error"})
    )

    with pytest.raises(Exception):
        github_provider.fetch_user_info("test_token")
