import json
import warnings
from typing import Annotated, Any, Literal

from cross_web import HTTPRequest, Response
from pydantic import (
    BaseModel,
    ConfigDict,
    Discriminator,
    Field,
    ValidationError,
)
from pydantic.type_adapter import TypeAdapter

from cross_auth.models.oauth_token_response import TokenResponse
from cross_auth.utils._pkce import validate_pkce

from ._authorization_code import (
    AUTH_CODE_KEY,
    AuthorizationCodeGrantData,
)
from ._context import Context
from ._password import _verify_password
from ._route import Route
from ._tokens import IssuedToken, TokenIssueRequest
from .exceptions import CrossAuthException, MFARequired
from .hooks import (
    AfterTokenAuthorizationCodeEvent,
    AfterTokenPasswordEvent,
    BeforeTokenAuthorizationCodeEvent,
    BeforeTokenPasswordEvent,
    UserSnapshot,
)


class AuthorizationCodeGrantRequest(BaseModel):
    grant_type: Literal["authorization_code"] = Field(
        description="The OAuth 2.0 grant type"
    )
    client_id: str = Field(description="The client identifier")
    client_secret: str | None = Field(
        None, description="The client secret (for confidential clients)", repr=False
    )
    code: str = Field(
        description="The authorization code received from the authorization server",
        repr=False,
    )
    redirect_uri: str = Field(
        description="The redirect URI used in the authorization request"
    )
    code_verifier: str = Field(description="The PKCE code verifier", repr=False)
    scope: str | None = Field(None, description="Space-delimited list of scopes")


class PasswordGrantRequest(BaseModel):
    # RFC 9700 section 2.4: the resource owner password grant MUST NOT be used.
    model_config = ConfigDict(json_schema_extra={"deprecated": True})

    grant_type: Literal["password"] = Field(description="The OAuth 2.0 grant type")
    client_id: str = Field(description="The client identifier")
    client_secret: str | None = Field(
        None, description="The client secret (for confidential clients)", repr=False
    )
    username: str = Field(description="The resource owner username")
    password: str = Field(description="The resource owner password", repr=False)
    scope: str | None = Field(None, description="Space-delimited list of scopes")


TokenRequest = Annotated[
    AuthorizationCodeGrantRequest | PasswordGrantRequest,
    Discriminator("grant_type"),
]
TokenRequestAdapter: TypeAdapter[TokenRequest] = TypeAdapter(TokenRequest)

# Finishes a password grant that answered mfa_required, with its mfa_token
# and an otp or recovery_code.
MFA_GRANT_TYPE = "urn:cross-auth:grant-type:mfa"


# Documents the MFA grant in the schema; /token reads it from the form itself.
class MFAGrantRequest(BaseModel):
    """Finishes a password grant that answered 403 mfa_required."""

    grant_type: Literal["urn:cross-auth:grant-type:mfa"] = Field(
        description="The Cross Auth MFA grant type"
    )
    client_id: str = Field(description="The client of the password grant")
    mfa_token: str = Field(description="The mfa_token the password grant returned")
    otp: str | None = Field(
        None, description="A code from the authenticator app; or recovery_code"
    )
    recovery_code: str | None = Field(
        None, description="A recovery code; or otp", repr=False
    )


class MFARequiredResponse(BaseModel):
    error: Literal["mfa_required"]
    error_description: str | None = None
    mfa_token: str = Field(description="Send it back with the MFA grant", repr=False)
    methods: list[str] = Field(description="Proofs the MFA grant accepts")


PASSWORD_GRANT_DEPRECATION = (
    "The OAuth password grant is deprecated (RFC 9700 section 2.4) and will be "
    "removed in Cross Auth 1.0. Use the authorization code grant with PKCE for "
    "SPA and native clients, or your own sign-in endpoint with authenticate() "
    "for first-party password login, then drop OAuthServer(password_grant=True)."
)


KnownTokenErrorType = Literal[
    "invalid_request",
    "invalid_client",
    "invalid_grant",
    "unauthorized_client",
    "unsupported_grant_type",
    "invalid_scope",
]
TokenErrorType = KnownTokenErrorType | str


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


def _bearer_token(issued: IssuedToken) -> TokenResponse:
    return TokenResponse(
        access_token=issued.token,
        token_type="Bearer",
        expires_in=issued.expires_in,
        scope="",
    )


def _token_success(data: TokenResponse) -> Response:
    return Response(
        status_code=200,
        body=data.model_dump_json(),
        headers={
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
        },
        cookies=[],
    )


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

    def token(
        self,
        request: HTTPRequest,
        context: Context,
    ) -> Response:
        input_data = dict(request.post_data)

        if input_data.get("grant_type") == MFA_GRANT_TYPE:
            return self._mfa_grant(input_data, context, request)

        if input_data.get("grant_type") == "password":
            # Refused before validation, so no legacy field is required and no
            # account is looked up.
            oauth_server = context.oauth_server
            if oauth_server is None or not oauth_server.password_grant:
                return self._error_response(
                    "unsupported_grant_type", "Grant type 'password' is not supported"
                )
            warnings.warn(PASSWORD_GRANT_DEPRECATION, DeprecationWarning, stacklevel=2)

        try:
            token_request = TokenRequestAdapter.validate_python(input_data)
        except ValidationError as e:
            return self._format_validation_error(e)

        # TODO: support confidential clients (client_secret)

        if isinstance(token_request, AuthorizationCodeGrantRequest):
            return self._authorization_code_grant(token_request, context, request)
        elif isinstance(token_request, PasswordGrantRequest):
            return self._password_grant(token_request, context, request)

    def _authorization_code_grant(
        self,
        request: AuthorizationCodeGrantRequest,
        context: Context,
        http_request: HTTPRequest,
    ) -> Response:
        code = request.code

        raw_authorization_data = context.secondary_storage.pop(
            AUTH_CODE_KEY.format(code=code)
        )

        if raw_authorization_data is None:
            return self._error_response(
                "invalid_grant",
                "Authorization code not found",
            )

        try:
            authorization_data = AuthorizationCodeGrantData.model_validate_json(
                raw_authorization_data
            )
        except ValidationError:
            return self._error_response(
                "invalid_grant",
                "Invalid authorization code data",
            )

        if authorization_data.is_expired:
            return self._error_response(
                "invalid_grant",
                "Authorization code has expired",
            )

        if authorization_data.redirect_uri != request.redirect_uri:
            return self._error_response(
                "invalid_grant",
                "Redirect URI does not match",
            )

        if authorization_data.client_id != request.client_id:
            return self._error_response(
                "invalid_grant",
                "Client ID does not match",
            )

        if not context.is_valid_redirect_uri(
            request.redirect_uri, client_id=request.client_id
        ):
            return self._error_response(
                "invalid_grant",
                "Redirect URI is no longer registered for this client",
            )

        if not validate_pkce(
            authorization_data.code_challenge,
            authorization_data.code_challenge_method,
            request.code_verifier,
        ):
            return self._error_response(
                "invalid_grant",
                "Invalid code challenge",
            )

        try:
            context.hooks.run_before(
                "token.authorization_code",
                BeforeTokenAuthorizationCodeEvent(
                    client_id=authorization_data.client_id,
                    user_id=authorization_data.user_id,
                    scope=request.scope,
                ),
            )
        except CrossAuthException as e:
            return self._error_response(e.error, e.error_description)

        try:
            issued = context.issue_token_result(
                TokenIssueRequest(
                    user_id=authorization_data.user_id,
                    client_id=authorization_data.client_id,
                    grant_type="authorization_code",
                    scope=request.scope,
                    http_request=http_request,
                    login_method=authorization_data.login_method,
                    mfa_method=authorization_data.mfa_method,
                )
            )
        except CrossAuthException as e:
            return self._error_response(e.error, e.error_description)

        token_data = _bearer_token(issued)

        after_event = AfterTokenAuthorizationCodeEvent(
            request=request,
            code=code,
            authorization_data=authorization_data,
            token_response=token_data,
        )
        issued.on_commit(
            lambda: context.hooks.run_after("token.authorization_code", after_event)
        )

        return _token_success(token_data)

    def _password_grant(
        self,
        request: PasswordGrantRequest,
        context: Context,
        http_request: HTTPRequest,
    ) -> Response:
        user = context.accounts_storage.find_user_by_email(
            context.normalize_email(request.username)
        )

        try:
            context.hooks.run_before(
                "token.password",
                BeforeTokenPasswordEvent(
                    client_id=request.client_id,
                    username=request.username,
                    user=None if user is None else UserSnapshot.of(user),
                    scope=request.scope,
                ),
            )
        except CrossAuthException as e:
            return self._error_response(e.error, e.error_description)

        valid = _verify_password(user, request.password, context.password_hasher)
        if not valid or user is None:
            return self._error_response("invalid_grant", "Invalid username or password")

        try:
            issued = context.issue_token_result(
                TokenIssueRequest(
                    user_id=str(user.id),
                    client_id=request.client_id,
                    scope=request.scope,
                    username=request.username,
                    http_request=http_request,
                    grant_type="password",
                    login_method="password",
                )
            )
        except MFARequired as required:
            assert context.mfa is not None
            started = context.mfa.start_challenge(
                required,
                kind="token",
                data={
                    "client_id": request.client_id,
                    "scope": request.scope,
                    "username": request.username,
                },
            )
            return Response(
                status_code=403,
                body=json.dumps(
                    {
                        "error": "mfa_required",
                        "error_description": required.error_description,
                        "mfa_token": started.challenge,
                        "methods": started.methods,
                    }
                ),
                headers={
                    "Content-Type": "application/json",
                    "Cache-Control": "no-store",
                },
            )
        except CrossAuthException as e:
            return self._error_response(e.error, e.error_description)

        token_data = _bearer_token(issued)

        after_event = AfterTokenPasswordEvent(
            client_id=request.client_id,
            username=request.username,
            user=user,
            scope=request.scope,
            token_response=token_data,
        )
        issued.on_commit(lambda: context.hooks.run_after("token.password", after_event))

        return _token_success(token_data)

    def _mfa_grant(
        self, data: dict[str, Any], context: Context, http_request: HTTPRequest
    ) -> Response:
        from ._mfa_flow import finish_challenge

        mfa_token = data.get("mfa_token")
        if context.mfa is None or not isinstance(mfa_token, str) or not mfa_token:
            return self._error_response("invalid_grant", "mfa_token is required")
        challenge = context.mfa.load_challenge(mfa_token)
        if challenge is None or challenge.kind != "token":
            return self._error_response("invalid_grant", "Unknown or expired mfa_token")
        # A password grant's continuation: refused once the grant is turned off.
        oauth_server = context.oauth_server
        if oauth_server is None or not oauth_server.password_grant:
            return self._error_response(
                "unsupported_grant_type", "Grant type 'password' is not supported"
            )
        if challenge.data.get("client_id") != data.get("client_id"):
            return self._error_response("invalid_grant", "Client ID does not match")
        otp = data.get("otp") or None
        recovery_code = data.get("recovery_code") or None
        try:
            finished = finish_challenge(
                http_request,
                context,
                mfa_token,
                kinds=("token",),
                code=otp if isinstance(otp, str) else None,
                recovery_code=recovery_code if isinstance(recovery_code, str) else None,
            )
        except CrossAuthException as e:
            if e.status_code == 429:
                return Response(
                    status_code=429,
                    body=TokenErrorResponse(
                        error=e.error, error_description=e.error_description
                    ).model_dump_json(exclude_none=True),
                    headers={"Content-Type": "application/json"},
                )
            return self._error_response(
                "invalid_grant" if e.error == "invalid_code" else e.error,
                e.error_description,
            )
        return finished.response

    def routes(self, *, password_grant: bool) -> list[Route]:
        # The route reads its own form, so FastAPI adds no components for these
        # models: inline them so the schema resolves without extra_schemas.
        code_grant = AuthorizationCodeGrantRequest.model_json_schema()
        grant_schemas: dict[str, dict[str, Any]] = {
            "AuthorizationCodeGrantRequest": code_grant
        }
        request_schema = code_grant
        # The password grant, and with it the MFA grant that finishes it.
        challenge_responses: dict[str, Any] = {}
        if password_grant:
            password_schema = PasswordGrantRequest.model_json_schema()
            mfa_schema = MFAGrantRequest.model_json_schema()
            grant_schemas["PasswordGrantRequest"] = password_schema
            grant_schemas["MFAGrantRequest"] = mfa_schema
            request_schema = {
                "oneOf": [code_grant, password_schema, mfa_schema],
                "title": "Request",
            }
            challenge_responses = {
                "403": {
                    "description": "The user needs a second factor: send the "
                    "MFA grant with mfa_token",
                    "content": {
                        "application/json": {
                            "schema": MFARequiredResponse.model_json_schema()
                        }
                    },
                },
                "429": {
                    "description": "Too many wrong codes; try again later",
                    "content": {
                        "application/json": {
                            "schema": TokenErrorResponse.model_json_schema()
                        }
                    },
                },
            }

        return [
            Route(
                path="/token",
                methods=["POST"],
                function=self.token,
                response_model=TokenResponse,
                operation_id="token",
                read_form_data=True,
                summary="OAuth 2.0 token endpoint",
                openapi={
                    "requestBody": {
                        "content": {
                            "application/x-www-form-urlencoded": {
                                "schema": request_schema
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
                                    "schema": TokenErrorResponse.model_json_schema()
                                }
                            },
                        },
                        **challenge_responses,
                    },
                },
                # Published for applications that merge them into their schema.
                openapi_schemas={
                    **grant_schemas,
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
                    "TokenErrorResponse": TokenErrorResponse.model_json_schema(),
                    "TokenResponse": TokenResponse.model_json_schema(),
                },
            ),
        ]
