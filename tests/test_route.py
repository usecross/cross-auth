import inspect
import json
from typing import get_args

from cross_web import Response
from fastapi import FastAPI
from fastapi.params import Body as FastAPIBody
from fastapi.testclient import TestClient

from cross_auth._route import PathParameter, Route


def _handler(request, context):
    return Response(status_code=204)


ITEM_ID_PARAMETER: PathParameter = {
    "name": "item_id",
    "in": "path",
    "required": True,
    "schema": {"type": "string", "title": "Item Id"},
}

OTHER_ID_PARAMETER: PathParameter = {
    "name": "other_id",
    "in": "path",
    "required": True,
    "schema": {"type": "string", "title": "Other Id"},
}


def _has_fastapi_body_parameter(endpoint) -> bool:
    return any(
        isinstance(metadata, FastAPIBody)
        for parameter in inspect.signature(endpoint).parameters.values()
        for metadata in get_args(parameter.annotation)
    )


def test_route_copies_path_parameters():
    parameters = [ITEM_ID_PARAMETER]

    route = Route("/items/{item_id}", ["GET"], _handler, path_parameters=parameters)
    parameters.append(OTHER_ID_PARAMETER)

    assert route.path_parameters == [ITEM_ID_PARAMETER]


def test_route_path_parameters_override_matching_openapi_parameters():
    route = Route(
        "/items/{item_id}",
        ["GET"],
        _handler,
        openapi={
            "parameters": [
                {
                    "name": "include_deleted",
                    "in": "query",
                    "schema": {"type": "boolean"},
                },
                {
                    "name": "item_id",
                    "in": "path",
                    "required": False,
                    "schema": {"type": "integer"},
                },
            ]
        },
        path_parameters=[ITEM_ID_PARAMETER],
    )

    assert route.get_openapi_extra() == {
        "parameters": [
            {
                "name": "include_deleted",
                "in": "query",
                "schema": {"type": "boolean"},
            },
            ITEM_ID_PARAMETER,
        ]
    }


def test_fastapi_endpoint_without_preload_is_sync(context):
    route = Route("/items", ["GET"], _handler)

    endpoint = route.to_fastapi_endpoint(context=context)

    assert not inspect.iscoroutinefunction(endpoint)


def test_fastapi_endpoint_with_body_preload_uses_fastapi_body(context):
    seen = {}

    def handler(request, context):
        seen["body"] = json.loads(request.body)
        return Response(status_code=204)

    route = Route("/items", ["POST"], handler, read_body=True)
    endpoint = route.to_fastapi_endpoint(context=context)

    assert not inspect.iscoroutinefunction(endpoint)
    assert _has_fastapi_body_parameter(endpoint)

    app = FastAPI()
    app.add_api_route(route.path, endpoint, methods=route.methods)
    client = TestClient(app)

    response = client.post("/items", json={"name": "patrick"})

    assert response.status_code == 204
    assert seen == {"body": {"name": "patrick"}}


def test_fastapi_endpoint_with_form_preload_uses_dependency(context):
    seen = {}

    def handler(request, context):
        seen["form_data"] = dict(request.post_data)
        return Response(status_code=204)

    route = Route("/items", ["POST"], handler, read_form_data=True)
    endpoint = route.to_fastapi_endpoint(context=context)

    assert not inspect.iscoroutinefunction(endpoint)

    app = FastAPI()
    app.add_api_route(route.path, endpoint, methods=route.methods)
    client = TestClient(app)

    response = client.post("/items", data={"name": "patrick"})

    assert response.status_code == 204
    assert seen == {"form_data": {"name": "patrick"}}
