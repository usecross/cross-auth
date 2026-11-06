"""Persisted provider attempts and their common authorization setup."""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, NamedTuple, TypedDict

from cross_web import Cookie, HTTPRequest
from pydantic import BaseModel, Field, ValidationError

from ._context import Context
from .social_providers.oauth import OAuth2Provider
from .utils._pkce import calculate_s256_challenge, generate_code_verifier
from .utils._url import construct_relative_url


FlowKind = Literal[
    # Sign in and set a session cookie in the browser.
    "session",
    # Sign in and return an authorization code for the client to exchange.
    "token",
    # Add a provider account to an authenticated user after the client redeems
    # a link code at finalize-link with its PKCE verifier.
    "link",
    # Add a provider account to an authenticated user during the callback,
    # then redirect back to the app without a separate finalize-link step.
    "connect",
]


class AuthRequest(BaseModel):
    """Stored state for an in-progress authorization at the provider.

    Keyed by `oauth:authorization_request:v2:{state}` in secondary storage.
    """

    flow: FlowKind
    provider_id: str
    state: str
    provider_code_verifier: str | None = None
    provider_data: dict[str, str] = Field(default_factory=dict)
    browser_binding: str
    expires_at: datetime

    # Session + connect flows: where to redirect the user after completion.
    next_url: str | None = None

    # Token flow: the client app's OAuth parameters.
    client_id: str | None = None
    client_redirect_uri: str | None = None
    client_state: str | None = None
    client_code_challenge: str | None = None
    client_code_challenge_method: Literal["S256"] | None = None

    # Link + connect flows: the user who initiated attaching a social account.
    user_id: str | None = None

    # Connect flow: also make the attached account a login method.
    allow_login: bool = False


class LinkCodeData(BaseModel):
    """Stored after a successful link callback; redeemed by finalize-link."""

    expires_at: datetime
    provider_id: str | None = None
    client_id: str
    redirect_uri: str
    code_challenge: str
    code_challenge_method: Literal["S256"]
    user_id: str
    provider_code: str
    provider_code_verifier: str | None = None
    provider_data: dict[str, str] = Field(default_factory=dict)
    client_state: str | None = None
    provider_callback_extra: dict[str, Any] | None = None


class InitiateLinkRequest(BaseModel):
    redirect_uri: str
    code_challenge: str
    code_challenge_method: Literal["S256"]
    client_id: str
    state: str | None = None


_AUTH_REQUEST_KEY = "oauth:authorization_request:v2:{state}"
_LINK_CODE_KEY = "oauth:link_request:v2:{code}"
_LINK_CODE_TTL = timedelta(minutes=10)
_AUTH_REQUEST_TTL = timedelta(minutes=10)


def _binding_cookie(
    request: HTTPRequest, context: Context, state: str, value: str, *, max_age: int
) -> Cookie:
    secure = (context.base_url or str(request.url)).startswith("https://")
    prefix = "__Host-" if secure else ""
    return Cookie(
        name=f"{prefix}cross_auth_oauth_{state}",
        value=value,
        secure=secure,
        path="/",
        max_age=max_age,
        httponly=True,
        samesite="lax",
    )


def _store_auth_request(
    context: Context, request: HTTPRequest, data: AuthRequest, binding: str
) -> Cookie:
    context.secondary_storage.set(
        _AUTH_REQUEST_KEY.format(state=data.state),
        data.model_dump_json(),
        ttl=int(_AUTH_REQUEST_TTL.total_seconds()),
    )
    return _binding_cookie(
        request,
        context,
        data.state,
        binding,
        max_age=int(_AUTH_REQUEST_TTL.total_seconds()),
    )


def _load_auth_request(context: Context, state: str) -> AuthRequest | None:
    raw = context.secondary_storage.get(_AUTH_REQUEST_KEY.format(state=state))
    if raw is None:
        return None
    try:
        data = AuthRequest.model_validate_json(raw)
    except ValidationError:
        return None

    if data.expires_at <= datetime.now(tz=timezone.utc):
        return None
    return data


def _generate_provider_pkce(
    provider: OAuth2Provider,
) -> tuple[str | None, str | None, str | None]:
    if not provider.supports_pkce:
        return None, None, None
    verifier = generate_code_verifier()
    return verifier, calculate_s256_challenge(verifier), "S256"


def _proxy_redirect_uri(request: HTTPRequest, context: Context) -> str:
    return construct_relative_url(str(request.url), "callback", context.base_url)


@dataclass(frozen=True)
class ClientAuthorization:
    client_id: str
    redirect_uri: str
    state: str | None
    code_challenge: str
    code_challenge_method: Literal["S256"]


@dataclass(frozen=True)
class SessionAuthorization:
    next_url: str
    login_hint: str | None


@dataclass(frozen=True)
class ConnectAuthorization:
    user_id: str
    next_url: str
    allow_login: bool


@dataclass(frozen=True)
class TokenAuthorization:
    client: ClientAuthorization
    login_hint: str | None


@dataclass(frozen=True)
class LinkAuthorization:
    user_id: str
    client: ClientAuthorization


AuthorizationFlow = (
    SessionAuthorization | ConnectAuthorization | TokenAuthorization | LinkAuthorization
)


class _AttemptFields(TypedDict):
    provider_id: str
    state: str
    provider_code_verifier: str | None
    provider_data: dict[str, str]
    browser_binding: str
    expires_at: datetime


class _ClientFields(TypedDict):
    client_id: str
    client_redirect_uri: str
    client_state: str | None
    client_code_challenge: str
    client_code_challenge_method: Literal["S256"]


class _AuthorizationOptions(TypedDict, total=False):
    login_hint: str | None


def _client_fields(client: ClientAuthorization) -> _ClientFields:
    return {
        "client_id": client.client_id,
        "client_redirect_uri": client.redirect_uri,
        "client_state": client.state,
        "client_code_challenge": client.code_challenge,
        "client_code_challenge_method": client.code_challenge_method,
    }


def _auth_request(flow: AuthorizationFlow, common: _AttemptFields) -> AuthRequest:
    if isinstance(flow, SessionAuthorization):
        return AuthRequest(flow="session", next_url=flow.next_url, **common)
    if isinstance(flow, ConnectAuthorization):
        return AuthRequest(
            flow="connect",
            user_id=flow.user_id,
            next_url=flow.next_url,
            allow_login=flow.allow_login,
            **common,
        )
    if isinstance(flow, TokenAuthorization):
        return AuthRequest(flow="token", **_client_fields(flow.client), **common)
    return AuthRequest(
        flow="link", user_id=flow.user_id, **_client_fields(flow.client), **common
    )


class StartedAuthorization(NamedTuple):
    data: AuthRequest
    authorization_url: str
    binding_cookie: Cookie


def begin_authorization(
    provider: OAuth2Provider,
    request: HTTPRequest,
    context: Context,
    flow: AuthorizationFlow,
) -> StartedAuthorization:
    state = secrets.token_hex(16)
    verifier, challenge, challenge_method = _generate_provider_pkce(provider)
    provider_data = provider.get_authorization_data()
    binding = secrets.token_urlsafe(32)
    data = _auth_request(
        flow,
        {
            "provider_id": provider.id,
            "state": state,
            "provider_code_verifier": verifier,
            "provider_data": provider_data,
            "browser_binding": hashlib.sha256(binding.encode()).hexdigest(),
            "expires_at": datetime.now(tz=timezone.utc) + _AUTH_REQUEST_TTL,
        },
    )
    cookie = _store_auth_request(context, request, data, binding)
    options: _AuthorizationOptions = {}
    if isinstance(flow, (SessionAuthorization, TokenAuthorization)):
        options["login_hint"] = flow.login_hint
    authorization_url = provider.build_authorization_url(
        provider_data=provider_data,
        state=state,
        redirect_uri=_proxy_redirect_uri(request, context),
        request=request,
        code_challenge=challenge,
        code_challenge_method=challenge_method,
        **options,
    )
    return StartedAuthorization(data, authorization_url, cookie)
