"""A fake Google for browser tests: real RS256 ID tokens, mocked network.

Token and JWKS requests are answered by respx. ID tokens are signed with a
test RSA key published at Google's JWKS URL, so the provider verifies them
exactly as it verifies real ones.
"""

from __future__ import annotations

import base64
import hashlib
import itertools
import json
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import respx
from cryptography.hazmat.primitives.asymmetric import rsa
from django.http import HttpResponseBase
from django.test import Client
from jwt.algorithms import RSAAlgorithm

from cross_auth.social_providers.google import GoogleProvider

CLIENT_ID = "test-client-id"
CALLBACK = "http://testserver/auth/google/callback"


@dataclass
class Authorization:
    """What the browser carried to Google's authorization endpoint."""

    url: str
    params: dict[str, str]

    @property
    def state(self) -> str:
        return self.params["state"]


@dataclass
class Account:
    sub: str = "google-sub-1"
    email: str | None = "person@gmail.com"
    email_verified: bool | None = True
    name: str = "Pat Example"


@dataclass
class FakeGoogle:
    router: respx.MockRouter
    key: rsa.RSAPrivateKey = field(
        default_factory=lambda: rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
    )
    # Codes Google has issued: code -> (account, nonce, code_challenge).
    codes: dict[str, tuple[Account, str, str]] = field(default_factory=dict)
    # Never reuse a code name, even after earlier codes were exchanged.
    code_numbers: Iterator[int] = field(default_factory=itertools.count)
    token_requests: list[dict[str, str]] = field(default_factory=list)

    def install(self) -> None:
        jwk = json.loads(RSAAlgorithm.to_jwk(self.key.public_key()))
        jwk.update({"kid": "test-key", "alg": "RS256", "use": "sig"})
        self.router.get(GoogleProvider.jwks_uri).mock(
            return_value=httpx.Response(200, json={"keys": [jwk]})
        )
        self.router.post(GoogleProvider.token_endpoint).mock(side_effect=self._token)

    def authorize(self, response: HttpResponseBase) -> Authorization:
        """Follow the redirect to Google and return the request it carried."""
        assert response.status_code == 302, response.status_code
        url = response["Location"]
        parsed = urlparse(url)
        assert f"{parsed.scheme}://{parsed.netloc}{parsed.path}" == (
            GoogleProvider.authorization_endpoint
        )
        params = {key: values[0] for key, values in parse_qs(parsed.query).items()}
        return Authorization(url=url, params=params)

    def approve(self, authorization: Authorization, account: Account) -> str:
        """Let the user consent; return the code Google redirects back with."""
        code = f"code-{next(self.code_numbers)}"
        self.codes[code] = (
            account,
            authorization.params["nonce"],
            authorization.params["code_challenge"],
        )
        return code

    def callback(
        self,
        client: Client,
        authorization: Authorization,
        account: Account | None = None,
        *,
        provider: str = "google",
    ) -> HttpResponseBase:
        code = self.approve(authorization, account or Account())
        return client.get(
            f"/auth/{provider}/callback", {"state": authorization.state, "code": code}
        )

    def _token(self, request: httpx.Request) -> httpx.Response:
        form = {
            key: values[0] for key, values in parse_qs(request.content.decode()).items()
        }
        self.token_requests.append(form)
        issued = self.codes.pop(form.get("code", ""), None)
        if issued is None:
            return httpx.Response(400, json={"error": "invalid_grant"})
        account, nonce, challenge = issued
        verifier_hash = hashlib.sha256(form.get("code_verifier", "").encode()).digest()
        expected = base64.urlsafe_b64encode(verifier_hash).rstrip(b"=").decode()
        if expected != challenge or form.get("redirect_uri") != CALLBACK:
            return httpx.Response(400, json={"error": "invalid_grant"})
        return httpx.Response(
            200,
            json={
                "access_token": "google-access-token",
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": "openid email profile",
                "id_token": self.id_token(account, nonce=nonce),
            },
        )

    def id_token(self, account: Account, *, nonce: str, **overrides: Any) -> str:
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": "https://accounts.google.com",
            "aud": CLIENT_ID,
            "sub": account.sub,
            "iat": now,
            "exp": now + 300,
            "nonce": nonce,
            "name": account.name,
        }
        if account.email is not None:
            claims["email"] = account.email
        if account.email_verified is not None:
            claims["email_verified"] = account.email_verified
        claims.update(overrides)
        return jwt.encode(
            claims, self.key, algorithm="RS256", headers={"kid": "test-key"}
        )
