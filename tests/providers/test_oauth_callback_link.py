import json
from datetime import datetime, timezone

import pytest
import time_machine
from cross_web import AsyncHTTPRequest, TestingRequestAdapter
from inline_snapshot import snapshot

from cross_auth._context import Context, SecondaryStorage
from cross_auth.social_providers.oauth import OAuth2Provider

from ..conftest import MemoryAccountsStorage

pytestmark = pytest.mark.asyncio


@pytest.fixture
def valid_link_callback_request(
    secondary_storage: SecondaryStorage,
) -> AsyncHTTPRequest:
    secondary_storage.set(
        "oauth:authorization_request:test_state",
        json.dumps(
            {
                "client_id": "my_app_client_id",
                "redirect_uri": "http://valid-frontend.com/link",
                "login_hint": "test_login_hint",
                "state": "test_state",
                "client_state": "test_client_state",
                "code_challenge": "test",
                "code_challenge_method": "S256",
                "link": True,
                "user_id": "test",
            }
        ),
    )

    return AsyncHTTPRequest(
        TestingRequestAdapter(
            method="GET",
            url="http://localhost:8000/test/callback",
            query_params={
                "code": "test_code",
                "state": "test_state",
            },
        )
    )


@time_machine.travel(datetime(2012, 10, 1, 1, 0, tzinfo=timezone.utc), tick=False)
async def test_stores_link_data(
    oauth_provider: OAuth2Provider,
    context: Context,
    valid_link_callback_request: AsyncHTTPRequest,
    accounts_storage: MemoryAccountsStorage,
    secondary_storage: SecondaryStorage,
) -> None:
    accounts_storage.data = {}

    response = await oauth_provider.callback(valid_link_callback_request, context)

    assert response.status_code == 302
    assert response.headers is not None
    assert response.headers["Location"] == snapshot(
        "http://valid-frontend.com/link?link_code=a-totally-valid-code"
    )

    assert accounts_storage.data == {}

    assert secondary_storage.get("oauth:link_request:test_state") == snapshot(None)
