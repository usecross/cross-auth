from typing import Generator

import pytest
from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi
from fastapi.testclient import TestClient

from cross_auth._context import AccountsStorage, SecondaryStorage
from cross_auth.router import AuthRouter


@pytest.fixture
def test_app(
    secondary_storage: SecondaryStorage,
    accounts_storage: AccountsStorage,
) -> FastAPI:
    app = FastAPI()

    router = AuthRouter(
        providers=[],
        secondary_storage=secondary_storage,
        accounts_storage=accounts_storage,
        get_user_from_request=lambda _: None,
        create_token=lambda _: ("", 0),
        trusted_origins=[],
    )

    app.include_router(router)

    def custom_openapi():
        openapi_schema = get_openapi(
            title="FastAPI",
            version="1.0.0",
            routes=app.routes,
        )
        new_schemas = openapi_schema["components"]["schemas"]
        new_schemas.update(router.extra_schemas)

        openapi_schema["components"]["schemas"] = new_schemas

        return openapi_schema

    app.openapi = custom_openapi  # type: ignore

    return app


@pytest.fixture
def client(test_app: FastAPI) -> Generator[TestClient, None, None]:
    with TestClient(test_app) as c:
        yield c
