"""Persisted authorization codes shared by their producer and redeemer."""

from datetime import datetime, timedelta, timezone
from typing import Literal

from pydantic import AwareDatetime, BaseModel

AUTH_CODE_KEY = "oauth:code:{code}"
AUTH_CODE_TTL = timedelta(minutes=10)


class AuthorizationCodeGrantData(BaseModel):
    user_id: str
    expires_at: AwareDatetime
    client_id: str
    redirect_uri: str

    code_challenge: str
    code_challenge_method: Literal["S256"]

    # How the user authenticated, e.g. the provider id. Codes stored by an
    # older version have no such field and parse with None.
    login_method: str | None = None

    @property
    def is_expired(self) -> bool:
        return datetime.now(tz=timezone.utc) > self.expires_at
