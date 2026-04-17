import json
from datetime import datetime, timezone

import pytest
import time_machine
from cross_web import AsyncHTTPRequest, TestingRequestAdapter
from inline_snapshot import snapshot

from cross_auth._context import Context, SecondaryStorage
from cross_auth.completions import TokenCompletion
from cross_auth.social_providers.oauth import OAuth2Provider

from ..conftest import MemoryAccountsStorage
from .conftest import dispatch_callback

pytestmark = pytest.mark.asyncio


@pytest.fixture
def valid_link_callback_request(
    secondary_storage: SecondaryStorage,
) -> AsyncHTTPRequest:
    secondary_storage.set(
        "oauth:authorization_request:test_state",
        json.dumps(
            {
                "kind": "token",
                "provider_id": "test",
                "state": "test_state",
                "provider_code_verifier": None,
                "completion_state": {
                    "sub_flow": "link",
                    "client_id": "my_app_client_id",
                    "redirect_uri": "http://valid-frontend.com/link",
                    "code_challenge": "test",
                    "code_challenge_method": "S256",
                    "client_state": "test_client_state",
                    "user_id": "test",
                },
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

    response = await dispatch_callback(
        oauth_provider, valid_link_callback_request, context, TokenCompletion()
    )

    assert response.status_code == 302
    assert response.headers is not None
    assert response.headers["Location"] == snapshot(
        "http://valid-frontend.com/link?link_code=a-totally-valid-code"
    )

    # Link flow does NOT exchange provider tokens at callback time —
    # it defers to /finalize-link. So no social account was created yet.
    assert accounts_storage.data == {}

    # And there's no finalized grant; the grant lives under the link_code.
    assert secondary_storage.get("oauth:link_request:test_state") == snapshot(None)
