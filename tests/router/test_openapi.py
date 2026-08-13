import warnings

from fastapi import FastAPI

from cross_auth.fastapi import CrossAuth


def test_callback_routes_have_unique_operation_ids(auth: CrossAuth):
    app = FastAPI()
    app.include_router(auth.router)

    with warnings.catch_warnings():
        warnings.filterwarnings("error", message="Duplicate Operation ID.*")
        schema = app.openapi()

    callback_operations = schema["paths"]["/fake/callback"]

    assert callback_operations["get"]["operationId"] == "fake_callback"
    assert callback_operations["post"]["operationId"] == "fake_callback_post"
