from collections.abc import Awaitable, Callable
from typing import Annotated, Any, get_args

from lia import AsyncHTTPRequest, Response
from pydantic import BaseModel

from ._context import Context


class Form:
    pass


def _get_fastapi_request_type(route: "Route") -> type[Any]:
    from fastapi import Request as FastAPIRequest
    from fastapi.params import Form as FastAPIForm

    RequestType: type[Any] = FastAPIRequest

    if route.request_type is not None:
        RequestType = route.request_type

        args = get_args(RequestType)

        if any(isinstance(arg, Form) for arg in args):
            RequestType = Annotated[RequestType, FastAPIForm()]  # type: ignore[assignment]

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

    def to_fastapi_endpoint(self, context: Context) -> Callable[..., Any]:
        from fastapi import Request as FastAPIRequest
        from fastapi import Response as FastAPIResponse

        async def wrapper(request: FastAPIRequest) -> FastAPIResponse:
            route_request = AsyncHTTPRequest.from_fastapi(request)

            route_response = await self.function(route_request, context)

            return route_response.to_fastapi()

        return wrapper
