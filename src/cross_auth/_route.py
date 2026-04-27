from collections.abc import Awaitable, Callable
from typing import Annotated, Any, Literal, TypedDict, get_args

from cross_web import AsyncHTTPRequest, Response
from pydantic import BaseModel

from ._context import Context


class Form:
    pass


PathParameter = TypedDict(
    "PathParameter",
    {
        "name": str,
        "in": Literal["path"],
        "required": Literal[True],
        "schema": dict[str, Any],
    },
)


def _get_fastapi_request_type(route: "Route") -> Any:
    from fastapi import Request as FastAPIRequest
    from fastapi.params import Form as FastAPIForm

    RequestType: Any = FastAPIRequest

    if route.request_type is not None:
        RequestType = route.request_type

        args = get_args(RequestType)

        if any(isinstance(arg, Form) for arg in args):
            RequestType = Annotated[RequestType, FastAPIForm()]

    return RequestType


class Route:
    def __init__(
        self,
        path: str,
        methods: list[str],
        function: Callable[[AsyncHTTPRequest, Context], Awaitable[Response]],
        response_model: type[BaseModel] | None = None,
        operation_id: str | None = None,
        request_type: Any | None = None,
        summary: str | None = None,
        openapi: dict[str, Any] | None = None,
        openapi_schemas: dict[str, Any] | None = None,
        path_parameters: list[PathParameter] | None = None,
    ):
        self.path = path
        self.methods = methods
        self.function = function
        self.response_model = response_model
        self.operation_id = operation_id
        self.request_type = request_type
        self.summary = summary
        self.openapi = openapi
        self.openapi_schemas = openapi_schemas
        self.path_parameters = list(path_parameters or [])

    def to_fastapi_endpoint(self, context: Context) -> Callable[..., Any]:
        from fastapi import Request as FastAPIRequest
        from fastapi import Response as FastAPIResponse

        async def wrapper(request: FastAPIRequest) -> FastAPIResponse:
            route_request = AsyncHTTPRequest.from_fastapi(request)

            route_response = await self.function(route_request, context)

            return route_response.to_fastapi()

        return wrapper

    def get_openapi_extra(self) -> dict[str, Any] | None:
        if not self.path_parameters:
            return self.openapi

        openapi = dict(self.openapi or {})
        path_parameter_keys = {
            (parameter["name"], parameter["in"]) for parameter in self.path_parameters
        }
        existing_parameters = [
            parameter
            for parameter in openapi.get("parameters", [])
            if (parameter.get("name"), parameter.get("in")) not in path_parameter_keys
        ]

        openapi["parameters"] = [*existing_parameters, *self.path_parameters]

        return openapi
