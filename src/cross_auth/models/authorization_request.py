from typing import Annotated, Literal, Union

from pydantic import BaseModel, Field


class BaseAuthorizationRequest(BaseModel):
    """Minimal fields for OAuth authorization flows."""

    redirect_uri: str
    state: str  # Internal state for the flow
    client_state: str | None = None  # Client's state for CSRF
    provider_code_verifier: str | None = None  # PKCE verifier for provider OAuth flow


class SessionFlowRequest(BaseAuthorizationRequest):
    """Session-based flow - creates cookie directly without code exchange."""

    flow_type: Literal["session"] = "session"


class ClientPKCERequest(BaseAuthorizationRequest):
    """Base for flows that require client PKCE exchange."""

    client_id: str  # The app's client_id (not the provider's)
    login_hint: str | None = None
    code_challenge: str  # Client's PKCE challenge
    code_challenge_method: Literal["S256"]


class CodeFlowRequest(ClientPKCERequest):
    """Standard OAuth authorization code flow with PKCE."""

    flow_type: Literal["code"] = "code"


class LinkFlowRequest(ClientPKCERequest):
    """Account linking flow."""

    flow_type: Literal["link"] = "link"
    user_id: str  # User who initiated the link


# Discriminated union for all authorization request types
AuthorizationRequestData = Annotated[
    Union[CodeFlowRequest, SessionFlowRequest, LinkFlowRequest],
    Field(discriminator="flow_type"),
]
