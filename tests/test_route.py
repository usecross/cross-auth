from cross_auth._route import PathParameter, Route


async def _handler(request, context): ...


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
