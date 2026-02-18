from cross_auth.social_providers.github import GitHubProvider


def test_noreply_disabled_by_default() -> None:
    provider = GitHubProvider(client_id="id", client_secret="secret")

    assert provider._allow_noreply_emails is False


def test_noreply_can_be_enabled() -> None:
    provider = GitHubProvider(
        client_id="id", client_secret="secret", allow_noreply_emails=True
    )

    assert provider._allow_noreply_emails is True
