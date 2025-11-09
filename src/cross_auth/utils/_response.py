import json
from typing import Self

from lia import Response as DuckResponse


class Response(DuckResponse):
    @classmethod
    def error(
        cls,
        error: str,
        error_description: str | None = None,
        error_uri: str | None = None,
        status_code: int = 400,
    ) -> Self:
        body = {"error": error}

        if error_description:
            body["error_description"] = error_description

        if error_uri:
            body["error_uri"] = error_uri

        return cls(
            status_code=status_code,
            body=json.dumps(body),
            headers={"Content-Type": "application/json"},
        )

    @classmethod
    def error_redirect(
        cls,
        redirect_uri: str,
        error: str,
        error_description: str | None = None,
        error_uri: str | None = None,
        state: str | None = None,
    ) -> Self:
        query_params = {"error": error}

        if error_description:
            query_params["error_description"] = error_description

        if error_uri:
            query_params["error_uri"] = error_uri

        if state:
            query_params["state"] = state

        return cls.redirect(redirect_uri, query_params=query_params)
