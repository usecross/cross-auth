from dataclasses import dataclass
from typing import Any, NotRequired, Protocol, TypedDict

from cross_web import AsyncHTTPRequest
from pydantic import BaseModel

from .._context import Context
from ..models.oauth_token_response import TokenResponse


class UserInfo(TypedDict, total=True):
    email: str | None
    id: str | int
    email_verified: bool | None
    name: NotRequired[str | None]


@dataclass
class ValidatedUserInfo:
    email: str | None
    provider_user_id: str
    email_verified: bool | None


class TokenExchangeParams(TypedDict, total=False):
    grant_type: str
    code: str
    redirect_uri: str
    client_id: str
    client_secret: str
    code_verifier: str


class OAuth2Exception(Exception):
    def __init__(self, error: str, error_description: str):
        self.error = error
        self.error_description = error_description


class CallbackData(BaseModel):
    code: str | None
    state: str | None
    error: str | None
    extra: dict[str, Any] | None = None  # Provider-specific data


class OAuth2ProviderProtocol(Protocol):
    id: str
    supports_pkce: bool
    trust_email: bool

    def can_auto_link(self, context: Context, email_verified: bool | None) -> bool: ...

    def allows_different_emails(
        self,
        context: Context,
        provider_email: str | None,
        user_email: str | None,
    ) -> bool: ...

    def build_authorization_url(
        self,
        state: str,
        redirect_uri: str,
        *,
        code_challenge: str | None = None,
        code_challenge_method: str | None = None,
        login_hint: str | None = None,
    ) -> str: ...

    async def extract_callback_params(
        self, request: AsyncHTTPRequest
    ) -> CallbackData: ...

    def exchange_code(
        self,
        code: str,
        redirect_uri: str,
        code_verifier: str | None = None,
    ) -> TokenResponse: ...

    def fetch_user_info(
        self,
        token_response: TokenResponse,
        context: Context,
        extra: dict[str, Any] | None = None,
    ) -> UserInfo: ...

    def validate_user_info(self, user_info: UserInfo) -> ValidatedUserInfo: ...
