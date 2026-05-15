from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from cross_web import (
    AsyncHTTPRequest,
    FormData,
    HTTPRequest,
    SyncHTTPRequestAdapter,
)
from cross_web.request._base import HTTPMethod, PathParams, QueryParams


# FastAPI/Starlette expose body and form parsing as async operations. Routes preload
# those values in async dependencies, then this adapter presents the remaining
# request data through cross-web's sync HTTPRequest API for handlers and hooks.
class HTTPRequestAdapter(SyncHTTPRequestAdapter):
    def __init__(
        self,
        request: AsyncHTTPRequest,
        *,
        body: str | bytes = b"",
        form_data: FormData | None = None,
    ) -> None:
        self._request = request
        self._body = body
        self._form_data = form_data or FormData(files={}, form={})

    @property
    def method(self) -> HTTPMethod:
        return self._request.method

    @property
    def query_params(self) -> QueryParams:
        return self._request.query_params

    @property
    def path_params(self) -> PathParams:
        return self._request.path_params

    @property
    def headers(self) -> Mapping[str, str]:
        return self._request.headers

    @property
    def content_type(self) -> str | None:
        return self._request.content_type

    @property
    def body(self) -> str | bytes:
        return self._body

    @property
    def post_data(self) -> Mapping[str, str | bytes]:
        return self._form_data.form

    @property
    def files(self) -> Mapping[str, Any]:
        return self._form_data.files

    def get_form_data(self) -> FormData:
        return self._form_data

    @property
    def url(self) -> str:
        return self._request.url

    @property
    def cookies(self) -> Mapping[str, str]:
        return self._request.cookies


def make_http_request(
    request: AsyncHTTPRequest,
    *,
    body: str | bytes = b"",
    form_data: FormData | None = None,
) -> HTTPRequest:
    return HTTPRequest(HTTPRequestAdapter(request, body=body, form_data=form_data))
