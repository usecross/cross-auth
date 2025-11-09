from fastapi import FastAPI
from inline_snapshot import snapshot


def test_router(test_app: FastAPI):
    assert test_app.openapi() == snapshot(
        {
            "openapi": "3.1.0",
            "info": {"title": "FastAPI", "version": "1.0.0"},
            "paths": {
                "/token": {
                    "post": {
                        "summary": "OAuth 2.0 token endpoint",
                        "operationId": "token",
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
                    }
                }
            },
            "components": {
                "schemas": {
                    "AuthorizationCodeGrantRequest": {
                        "properties": {
                            "grant_type": {
                                "type": "string",
                                "const": "authorization_code",
                                "title": "Grant Type",
                                "description": "The OAuth 2.0 grant type",
                            },
                            "client_id": {
                                "type": "string",
                                "title": "Client Id",
                                "description": "The client identifier",
                            },
                            "client_secret": {
                                "anyOf": [{"type": "string"}, {"type": "null"}],
                                "default": None,
                                "title": "Client Secret",
                                "description": "The client secret (for confidential clients)",
                            },
                            "code": {
                                "type": "string",
                                "title": "Code",
                                "description": "The authorization code received from the authorization server",
                            },
                            "redirect_uri": {
                                "type": "string",
                                "title": "Redirect Uri",
                                "description": "The redirect URI used in the authorization request",
                            },
                            "code_verifier": {
                                "type": "string",
                                "title": "Code Verifier",
                                "description": "The PKCE code verifier",
                            },
                            "scope": {
                                "anyOf": [{"type": "string"}, {"type": "null"}],
                                "default": None,
                                "title": "Scope",
                                "description": "Space-delimited list of scopes",
                            },
                        },
                        "type": "object",
                        "required": [
                            "grant_type",
                            "client_id",
                            "code",
                            "redirect_uri",
                            "code_verifier",
                        ],
                        "title": "AuthorizationCodeGrantRequest",
                    },
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
                    "PasswordGrantRequest": {
                        "properties": {
                            "grant_type": {
                                "type": "string",
                                "const": "password",
                                "title": "Grant Type",
                                "description": "The OAuth 2.0 grant type",
                            },
                            "client_id": {
                                "type": "string",
                                "title": "Client Id",
                                "description": "The client identifier",
                            },
                            "client_secret": {
                                "anyOf": [{"type": "string"}, {"type": "null"}],
                                "default": None,
                                "title": "Client Secret",
                                "description": "The client secret (for confidential clients)",
                            },
                            "username": {
                                "type": "string",
                                "title": "Username",
                                "description": "The resource owner username",
                            },
                            "password": {
                                "type": "string",
                                "title": "Password",
                                "description": "The resource owner password",
                            },
                            "scope": {
                                "anyOf": [{"type": "string"}, {"type": "null"}],
                                "default": None,
                                "title": "Scope",
                                "description": "Space-delimited list of scopes",
                            },
                        },
                        "type": "object",
                        "required": ["grant_type", "client_id", "username", "password"],
                        "title": "PasswordGrantRequest",
                    },
                    "TokenResponse": {
                        "properties": {
                            "token_type": {
                                "type": "string",
                                "title": "Token Type",
                                "description": "The type of token, usually 'Bearer'",
                            },
                            "access_token": {
                                "type": "string",
                                "title": "Access Token",
                                "description": "The issued access token",
                            },
                            "expires_in": {
                                "anyOf": [{"type": "integer"}, {"type": "null"}],
                                "default": None,
                                "title": "Expires In",
                                "description": "Lifetime of the access token in seconds",
                            },
                            "refresh_token": {
                                "anyOf": [{"type": "string"}, {"type": "null"}],
                                "default": None,
                                "title": "Refresh Token",
                                "description": "Token used to obtain new access tokens",
                            },
                            "refresh_token_expires_in": {
                                "anyOf": [{"type": "integer"}, {"type": "null"}],
                                "default": None,
                                "title": "Refresh Token Expires In",
                                "description": "Lifetime of the refresh token in seconds",
                            },
                            "scope": {
                                "anyOf": [{"type": "string"}, {"type": "null"}],
                                "default": None,
                                "title": "Scope",
                                "description": "Space-delimited list of scopes associated with the access token",
                            },
                        },
                        "type": "object",
                        "required": ["token_type", "access_token"],
                        "title": "TokenResponse",
                    },
                    "TokenErrorResponse": {
                        "properties": {
                            "error": {
                                "description": "Error code as per OAuth 2.0 specification",
                                "type": "string",
                                "enum": [
                                    "invalid_request",
                                    "invalid_client",
                                    "invalid_grant",
                                    "unauthorized_client",
                                    "unsupported_grant_type",
                                    "invalid_scope",
                                ],
                                "title": "Error",
                            },
                            "error_description": {
                                "anyOf": [{"type": "string"}, {"type": "null"}],
                                "default": None,
                                "description": "Human-readable explanation of the error",
                                "title": "Error Description",
                            },
                            "error_uri": {
                                "anyOf": [{"type": "string"}, {"type": "null"}],
                                "default": None,
                                "description": "URI to a web page with more information about the error",
                                "title": "Error Uri",
                            },
                        },
                        "type": "object",
                        "required": ["error"],
                        "title": "TokenErrorResponse",
                    },
                }
            },
        }
    )
