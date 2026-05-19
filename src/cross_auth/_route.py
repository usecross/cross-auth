import json
from collections.abc import Callable
from typing import Annotated, Any, Literal, TypedDict, get_args
from urllib.parse import parse_qsl

from cross_web import AsyncHTTPRequest, FormData, Response
from pydantic import BaseModel

from ._context import Context
from ._request import make_http_request


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


def _body_to_bytes(body: Any) -> bytes:
    if body is None:
        return b""

    if isinstance(body, bytes):
        return body

    if isinstance(body, str):
        return body.encode()

    return json.dumps(body).encode()


def _body_to_form_data(body: Any) -> FormData:
    if body is None:
        return FormData(files={}, form={})

    if isinstance(body, bytes):
        return FormData(
            files={},
            form=dict(parse_qsl(body.decode(), keep_blank_values=True)),
        )

    if isinstance(body, str):
        return FormData(files={}, form=dict(parse_qsl(body, keep_blank_values=True)))

    if isinstance(body, dict):
        return FormData(files={}, form=body)

    return FormData(files={}, form={})


def _form_data_request_body_openapi() -> dict[str, Any]:
    return {
        "content": {
            "application/x-www-form-urlencoded": {
                "schema": {
                    "additionalProperties": True,
                    "type": "object",
                    "title": "Form Data",
                }
            }
        }
    }


class Route:
    def __init__(
        self,
        path: str,
        methods: list[str],
        function: Callable[..., Response],
        response_model: type[BaseModel] | None = None,
        operation_id: str | None = None,
        request_type: Any | None = None,
        read_body: bool = False,
        read_form_data: bool = False,
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
        self.read_body = read_body
        self.read_form_data = read_form_data
        self.summary = summary
        self.openapi = openapi
        self.openapi_schemas = openapi_schemas
        self.path_parameters = list(path_parameters or [])

    def to_fastapi_endpoint(self, context: Context) -> Callable[..., Any]:
        from fastapi import Body
        from fastapi import Request as FastAPIRequest
        from fastapi import Response as FastAPIResponse

        def run_handler(
            request: FastAPIRequest,
            *,
            body: str | bytes = b"",
            form_data: FormData | None = None,
        ) -> FastAPIResponse:
            async_request = AsyncHTTPRequest.from_fastapi(request)
            route_request = make_http_request(
                async_request, body=body, form_data=form_data
            )
            route_response = self.function(route_request, context)

            return route_response.to_fastapi()

        if self.read_body or self.read_form_data:
            body_metadata = Body(
                media_type=(
                    "application/x-www-form-urlencoded"
                    if self.read_form_data
                    else "application/json"
                )
            )

            def wrapper(
                request: FastAPIRequest,
                body: Annotated[Any, body_metadata] = None,
            ) -> FastAPIResponse:
                form_data = (
                    _body_to_form_data(body)
                    if self.read_form_data and request.method == "POST"
                    else None
                )
                request_body = _body_to_bytes(body) if self.read_body else b""

                return run_handler(request, body=request_body, form_data=form_data)

            return wrapper

        def wrapper(request: FastAPIRequest) -> FastAPIResponse:
            return run_handler(request)

        return wrapper

    def get_openapi_extra(self) -> dict[str, Any] | None:
        openapi = dict(self.openapi or {})

        if self.read_form_data and "requestBody" not in openapi:
            openapi["requestBody"] = _form_data_request_body_openapi()

        if not self.path_parameters:
            return openapi or None

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
