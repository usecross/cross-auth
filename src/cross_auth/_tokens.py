from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

from cross_web import HTTPRequest

TokenGrantType = Literal["authorization_code", "password"]


@dataclass(frozen=True, kw_only=True)
class TokenIssueRequest:
    user_id: str
    client_id: str
    grant_type: TokenGrantType
    scope: str | None
    http_request: HTTPRequest
    username: str | None = None
    # How the user authenticated: "password" or the social provider's id.
    # None for authorization codes stored by a version that did not record it.
    login_method: str | None = None


TokenIssuer = Callable[[TokenIssueRequest], tuple[str, int]]
