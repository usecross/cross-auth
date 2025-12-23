from datetime import datetime, timedelta, timezone

from pydantic import BaseModel, Field, HttpUrl, RootModel


class TokenResponse(BaseModel):
    token_type: str = Field(description="The type of token, usually 'Bearer'")

    access_token: str = Field(description="The issued access token")
    expires_in: int | None = Field(
        None, description="Lifetime of the access token in seconds"
    )
    refresh_token: str | None = Field(
        None, description="Token used to obtain new access tokens"
    )
    refresh_token_expires_in: int | None = Field(
        None, description="Lifetime of the refresh token in seconds"
    )
    scope: str | None = Field(
        None,
        description="Space-delimited list of scopes associated with the access token",
    )
    id_token: str | None = Field(
        None,
        description="OpenID Connect ID token returned alongside access token",
    )

    @property
    def access_token_expires_at(self) -> datetime | None:
        if self.expires_in:
            return datetime.now(tz=timezone.utc) + timedelta(seconds=self.expires_in)

        return None

    @property
    def refresh_token_expires_at(self) -> datetime | None:
        if self.refresh_token_expires_in:
            return datetime.now(tz=timezone.utc) + timedelta(
                seconds=self.refresh_token_expires_in
            )

        return None


class TokenErrorResponse(BaseModel):
    error: str = Field(description="Error code as per OAuth 2.0 specification")
    error_description: str | None = Field(
        None, description="Human-readable explanation of the error"
    )
    error_uri: HttpUrl | None = Field(
        None, description="URI to a web page with more information about the error"
    )


class OAuth2TokenEndpointResponse(RootModel):
    root: TokenResponse | TokenErrorResponse

    def is_error(self) -> bool:
        return isinstance(self.root, TokenErrorResponse)
