import pytest

from cross_auth.social_providers.github import GitHubProvider

pytestmark = pytest.mark.asyncio


@pytest.fixture
def github_provider() -> GitHubProvider:
    return GitHubProvider(
        client_id="test_client_id", client_secret="test_client_secret"
    )


@pytest.fixture
def mock_user_info() -> dict:
    """Base GitHub user info response from /user endpoint."""
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
        "email": None,  # Email comes from /user/emails endpoint
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
def mock_emails_verified_primary() -> list[dict]:
    """GitHub emails response with verified primary email."""
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


@pytest.fixture
def mock_emails_unverified_primary() -> list[dict]:
    """GitHub emails response with unverified primary email."""
    return [
        {
            "email": "octocat@github.com",
            "verified": False,
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


@pytest.fixture
def mock_emails_noreply_only() -> list[dict]:
    """GitHub emails response with only noreply email (user hides email)."""
    return [
        {
            "email": "12345+octocat@users.noreply.github.com",
            "verified": True,
            "primary": True,
            "visibility": None,
        },
    ]


@pytest.fixture
def mock_emails_noreply_and_unverified() -> list[dict]:
    """GitHub emails with noreply primary and unverified secondary."""
    return [
        {
            "email": "12345+octocat@users.noreply.github.com",
            "verified": True,
            "primary": True,
            "visibility": None,
        },
        {
            "email": "octocat@example.com",
            "verified": False,
            "primary": False,
            "visibility": "private",
        },
    ]


@pytest.fixture
def mock_emails_noreply_and_verified() -> list[dict]:
    """GitHub emails with noreply primary but verified secondary."""
    return [
        {
            "email": "12345+octocat@users.noreply.github.com",
            "verified": True,
            "primary": True,
            "visibility": None,
        },
        {
            "email": "octocat@example.com",
            "verified": True,
            "primary": False,
            "visibility": "private",
        },
    ]


@pytest.fixture
def mock_emails_all_unverified() -> list[dict]:
    """GitHub emails response with no verified emails."""
    return [
        {
            "email": "octocat@github.com",
            "verified": False,
            "primary": True,
            "visibility": "public",
        },
        {
            "email": "octocat@example.com",
            "verified": False,
            "primary": False,
            "visibility": "private",
        },
    ]


@pytest.fixture
def mock_emails_empty() -> list[dict]:
    """GitHub emails response with no emails."""
    return []
