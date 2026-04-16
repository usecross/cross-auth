from datetime import datetime, timezone
from typing import Annotated, Literal, cast

from cross_web import AsyncHTTPRequest, Response
from pydantic import AwareDatetime, BaseModel, Discriminator, Field, ValidationError
from pydantic.type_adapter import TypeAdapter

from cross_auth.models.oauth_token_response import TokenResponse
from cross_auth.utils._pkce import validate_pkce

from ._context import Context
from ._password import authenticate as authenticate_password
from ._route import Form, Route
from .exceptions import CrossAuthException


class AuthorizationCodeGrantRequest(BaseModel):
    grant_type: Literal["authorization_code"] = Field(
        description="The OAuth 2.0 grant type"
    )
    client_id: str = Field(description="The client identifier")
    client_secret: str | None = Field(
        None, description="The client secret (for confidential clients)"
    )
    code: str = Field(
        description="The authorization code received from the authorization server"
    )
    redirect_uri: str = Field(
        description="The redirect URI used in the authorization request"
    )
    code_verifier: str = Field(description="The PKCE code verifier")
    scope: str | None = Field(None, description="Space-delimited list of scopes")


class PasswordGrantRequest(BaseModel):
    grant_type: Literal["password"] = Field(description="The OAuth 2.0 grant type")
    client_id: str = Field(description="The client identifier")
    client_secret: str | None = Field(
        None, description="The client secret (for confidential clients)"
    )
    username: str = Field(description="The resource owner username")
    password: str = Field(description="The resource owner password")
    scope: str | None = Field(None, description="Space-delimited list of scopes")


TokenRequest = Annotated[
    AuthorizationCodeGrantRequest | PasswordGrantRequest,
    Discriminator("grant_type"),
    Form(),
]
TokenRequestAdapter: TypeAdapter[TokenRequest] = TypeAdapter(TokenRequest)


TokenErrorType = Literal[
    "invalid_request",
    "invalid_client",
    "invalid_grant",
    "unauthorized_client",
    "unsupported_grant_type",
    "invalid_scope",
]


class TokenErrorResponse(BaseModel):
    error: TokenErrorType = Field(
        description="Error code as per OAuth 2.0 specification"
    )
    error_description: str | None = Field(
        default=None, description="Human-readable explanation of the error"
    )
    error_uri: str | None = Field(
        default=None,
        description="URI to a web page with more information about the error",
    )


class AuthorizationCodeGrantData(BaseModel):
    user_id: str
    expires_at: AwareDatetime
    client_id: str
    redirect_uri: str

    # PKCE
    code_challenge: str
    code_challenge_method: Literal["S256"]

    @property
    def is_expired(self) -> bool:
        return datetime.now(tz=timezone.utc) > self.expires_at


class Issuer:
    def _error_response(
        self,
        error: TokenErrorType,
        error_description: str | None = None,
        error_uri: str | None = None,
    ) -> Response:
        body = TokenErrorResponse(error=error)

        if error_description:
            body.error_description = error_description

        if error_uri:
            body.error_uri = error_uri

        return Response(
            status_code=400,
            body=body.model_dump_json(exclude_none=True),
            headers={"Content-Type": "application/json"},
        )

    def _format_validation_error(self, e: ValidationError) -> Response:
        errors = e.errors()

        error_type: TokenErrorType = "invalid_request"

        if not errors:
            return self._error_response(error_type, "Validation error")

        first_error = errors[0]
        field = first_error["loc"][-1] if first_error["loc"] else None

        match {"field": field, "type": first_error["type"]}:
            case {"type": "union_tag_not_found"}:
                message = "grant_type is required"
            case {"type": "union_tag_invalid"}:
                value = first_error["input"]["grant_type"]
                message = f"Grant type '{value}' is not supported"
                error_type = "unsupported_grant_type"
            case {"type": "missing", "field": field}:
                message = f"{field} is required"
            case _:
                message = f"Validation error: {first_error['type']}"

        return self._error_response(error_type, message)

    async def token(self, request: AsyncHTTPRequest, context: Context) -> Response:
        form_data = await request.get_form_data()

        try:
            token_request = TokenRequestAdapter.validate_python(form_data.form)
        except ValidationError as e:
            return self._format_validation_error(e)

        # TODO: validate client_id exists in client registry
        # TODO: support confidential clients (client_secret)

        if isinstance(token_request, AuthorizationCodeGrantRequest):
            return self._authorization_code_grant(token_request, context)
        elif isinstance(token_request, PasswordGrantRequest):
            return self._password_grant(token_request, context)

    def _authorization_code_grant(
        self, request: AuthorizationCodeGrantRequest, context: Context
    ) -> Response:
        try:
            raw_authorization_data = context.secondary_storage.pop(
                f"oauth:code:{request.code}"
            )

            if raw_authorization_data is None:
                raise CrossAuthException(
                    "invalid_grant",
                    "Authorization code not found",
                )

            try:
                authorization_data = AuthorizationCodeGrantData.model_validate_json(
                    raw_authorization_data
                )
            except ValidationError as e:
                raise CrossAuthException(
                    "invalid_grant",
                    "Invalid authorization code data",
                ) from e

            if authorization_data.is_expired:
                raise CrossAuthException(
                    "invalid_grant",
                    "Authorization code has expired",
                )

            if authorization_data.redirect_uri != request.redirect_uri:
                raise CrossAuthException(
                    "invalid_grant",
                    "Redirect URI does not match",
                )

            if authorization_data.client_id != request.client_id:
                raise CrossAuthException(
                    "invalid_grant",
                    "Client ID does not match",
                )

            if authorization_data.code_challenge_method != "S256":
                raise CrossAuthException(
                    "invalid_request",
                    "Unsupported code challenge method",
                )

            if not validate_pkce(
                authorization_data.code_challenge,
                authorization_data.code_challenge_method,
                request.code_verifier,
            ):
                raise CrossAuthException(
                    "invalid_grant",
                    "Invalid code challenge",
                )

        except CrossAuthException as e:
            return self._error_response(
                cast(TokenErrorType, e.error), e.error_description
            )

        return self._issue_access_token_response(authorization_data.user_id, context)

    def _issue_access_token_response(self, user_id: str, context: Context) -> Response:
        token, expires_in = context.create_token(user_id)

        token_data = TokenResponse(
            access_token=token,
            token_type="Bearer",
            expires_in=expires_in,
            refresh_token=None,
            refresh_token_expires_in=None,
            # TODO: figure out scopes
            scope="",
        )

        headers = {
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
        }

        return Response(
            status_code=200,
            body=token_data.model_dump_json(),
            headers=headers,
            cookies=[],
        )

    def _password_grant(
        self, request: PasswordGrantRequest, context: Context
    ) -> Response:
        user = authenticate_password(
            request.username,
            request.password,
            context.accounts_storage,
        )

        if user is None:
            return self._error_response("invalid_grant", "Invalid username or password")

        return self._issue_access_token_response(str(user.id), context)

    @property
    def routes(self) -> list[Route]:
        return [
            Route(
                path="/token",
                methods=["POST"],
                function=self.token,
                response_model=TokenResponse,
                operation_id="token",
                request_type=TokenRequest,
                summary="OAuth 2.0 token endpoint",
                openapi={
                    "requestBody": {
                        "content": {
                            "application/x-www-form-urlencoded": {
                                "schema": {
                                    "oneOf": [
                                        {
                                            "$ref": "#/components/schemas/AuthorizationCodeGrantRequest"
                                        },
                                        {
                                            "$ref": "#/components/schemas/PasswordGrantRequest"
                                        },
                                    ],
                                    "title": "Request",
                                    "discriminator": {
                                        "propertyName": "grant_type",
                                        "mapping": {
                                            "authorization_code": "#/components/schemas/AuthorizationCodeGrantRequest",
                                            "password": "#/components/schemas/PasswordGrantRequest",
                                        },
                                    },
                                }
                            }
                        },
                        "required": True,
                    },
                    "responses": {
                        "200": {
                            "description": "Successful token response",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "#/components/schemas/TokenResponse"
                                    }
                                }
                            },
                        },
                        "400": {
                            "description": "Bad request - invalid parameters or grant",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "#/components/schemas/TokenErrorResponse"
                                    }
                                }
                            },
                        },
                    },
                },
                openapi_schemas={
                    "AuthorizationCodeGrantRequest": AuthorizationCodeGrantRequest.model_json_schema(),
                    "HTTPValidationError": {
                        "properties": {
                            "detail": {
                                "items": {
                                    "$ref": "#/components/schemas/ValidationError"
                                },
                                "type": "array",
                                "title": "Detail",
                            }
                        },
                        "type": "object",
                        "title": "HTTPValidationError",
                    },
                    "PasswordGrantRequest": PasswordGrantRequest.model_json_schema(),
                    "TokenErrorResponse": TokenErrorResponse.model_json_schema(),
                    "TokenResponse": TokenResponse.model_json_schema(),
                },
            ),
        ]
