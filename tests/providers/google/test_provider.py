import json
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import parse_qs, urlparse
from unittest.mock import MagicMock

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from cross_auth.models.oauth_token_response import TokenResponse
from cross_auth.social_providers.google import GoogleProvider


def test_google_provider_defaults() -> None:
    provider = GoogleProvider(
        client_id="google-client-id",
        client_secret="google-client-secret",
    )

    assert provider.id == "google"
    assert provider.authorization_endpoint == (
        "https://accounts.google.com/o/oauth2/v2/auth"
    )
    assert provider.token_endpoint == "https://oauth2.googleapis.com/token"
    assert provider.jwks_uri == "https://www.googleapis.com/oauth2/v3/certs"
    assert provider.issuer == ["https://accounts.google.com", "accounts.google.com"]
    assert provider.jwks_cache_key == "google:jwks"
    assert provider.scopes == ["openid", "email", "profile"]
    assert provider.supports_pkce is True
    assert provider.trust_email is False


def test_google_provider_endpoint_overrides() -> None:
    provider = GoogleProvider(
        client_id="google-client-id",
        client_secret="google-client-secret",
        authorization_endpoint="https://mock.example/o/oauth2/v2/auth",
        token_endpoint="https://mock.example/token",
        jwks_uri="https://mock.example/oauth2/v3/certs",
    )

    assert provider.authorization_endpoint == "https://mock.example/o/oauth2/v2/auth"
    assert provider.token_endpoint == "https://mock.example/token"
    assert provider.jwks_uri == "https://mock.example/oauth2/v3/certs"


def test_google_authorization_url() -> None:
    provider = GoogleProvider(
        client_id="google-client-id",
        client_secret="google-client-secret",
    )

    auth_url = provider.build_authorization_url(
        state="state-123",
        redirect_uri="https://app.example/auth/google/callback",
        code_challenge="challenge",
        code_challenge_method="S256",
        login_hint="user@example.com",
    )
    parsed = urlparse(auth_url)
    query = parse_qs(parsed.query)

    assert parsed.scheme == "https"
    assert parsed.netloc == "accounts.google.com"
    assert parsed.path == "/o/oauth2/v2/auth"
    assert query == {
        "client_id": ["google-client-id"],
        "scope": ["openid email profile"],
        "redirect_uri": ["https://app.example/auth/google/callback"],
        "response_type": ["code"],
        "state": ["state-123"],
        "code_challenge": ["challenge"],
        "code_challenge_method": ["S256"],
        "login_hint": ["user@example.com"],
    }


def test_extra_authorization_params_are_appended() -> None:
    provider = GoogleProvider(
        client_id="google-client-id",
        client_secret="google-client-secret",
        extra_authorization_params={
            "access_type": "offline",
            "prompt": "consent",
            "hd": "example.com",
            "include_granted_scopes": "true",
        },
    )

    url = provider.build_authorization_url(
        state="state-123",
        redirect_uri="https://app.example/auth/google/callback",
        code_challenge="challenge",
        code_challenge_method="S256",
    )
    query = parse_qs(urlparse(url).query)

    assert query["access_type"] == ["offline"]
    assert query["prompt"] == ["consent"]
    assert query["hd"] == ["example.com"]
    assert query["include_granted_scopes"] == ["true"]


def test_extra_authorization_params_cannot_override_required() -> None:
    provider = GoogleProvider(
        client_id="google-client-id",
        client_secret="google-client-secret",
        extra_authorization_params={
            "client_id": "hijacked",
            "state": "hijacked",
            "redirect_uri": "https://evil.example/cb",
        },
    )

    url = provider.build_authorization_url(
        state="state-123",
        redirect_uri="https://app.example/auth/google/callback",
        code_challenge="challenge",
        code_challenge_method="S256",
    )
    query = parse_qs(urlparse(url).query)

    assert query["client_id"] == ["google-client-id"]
    assert query["state"] == ["state-123"]
    assert query["redirect_uri"] == ["https://app.example/auth/google/callback"]


def test_extract_user_info_from_claims() -> None:
    provider = GoogleProvider(
        client_id="google-client-id",
        client_secret="google-client-secret",
    )

    user_info = provider.extract_user_info_from_claims(
        {
            "sub": "google-user-123",
            "email": "user@example.com",
            "email_verified": True,
            "name": "Test User",
            "picture": "https://example.com/avatar.png",
        }
    )

    assert user_info == {
        "id": "google-user-123",
        "email": "user@example.com",
        "email_verified": True,
        "name": "Test User",
    }


def test_fetch_user_info_validates_rs256_id_token() -> None:
    provider = GoogleProvider(
        client_id="google-client-id",
        client_secret="google-client-secret",
    )
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_jwk = json.loads(RSAAlgorithm.to_jwk(private_key.public_key()))
    public_jwk["kid"] = "google-key-1"
    public_jwk["alg"] = "RS256"

    id_token = jwt.encode(
        {
            "iss": "https://accounts.google.com",
            "aud": "google-client-id",
            "sub": "google-user-123",
            "email": "user@example.com",
            "email_verified": True,
            "name": "Test User",
            "exp": datetime.now(tz=UTC) + timedelta(minutes=5),
            "iat": datetime.now(tz=UTC),
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "google-key-1"},
    )

    secondary_storage = MagicMock()
    secondary_storage.get.return_value = json.dumps({"keys": [public_jwk]})
    context = MagicMock()
    context.secondary_storage = secondary_storage

    user_info = provider.fetch_user_info(
        TokenResponse(
            token_type="Bearer",
            access_token="google-access-token",
            id_token=id_token,
        ),
        context,
    )

    assert user_info["id"] == "google-user-123"
    assert user_info["email"] == "user@example.com"
    assert user_info["email_verified"] is True


def test_jwks_ttl_from_cache_control() -> None:
    parse = GoogleProvider._ttl_from_cache_control

    # Honors max-age within bounds
    assert parse("public, max-age=3600, must-revalidate") == 3600
    assert parse("MAX-AGE=120, public") == 300  # clamped to floor
    assert parse("max-age=200000") == 86400  # clamped to ceiling

    # Fallback when header missing or no max-age
    assert parse(None) == 3600
    assert parse("no-cache") == 3600
    assert parse("") == 3600


def test_fetch_jwks_uses_response_cache_control(monkeypatch) -> None:
    provider = GoogleProvider(
        client_id="google-client-id",
        client_secret="google-client-secret",
    )

    captured_ttl: dict[str, int] = {}

    def fake_get(url: str) -> Any:
        response = MagicMock()
        response.raise_for_status.return_value = None
        response.json.return_value = {"keys": []}
        response.headers = {"cache-control": "public, max-age=7200"}
        return response

    secondary_storage = MagicMock()
    secondary_storage.get.return_value = None

    def fake_set(key: str, value: str, ttl: int) -> None:
        captured_ttl["ttl"] = ttl

    secondary_storage.set.side_effect = fake_set

    monkeypatch.setattr("cross_auth.social_providers.oidc.httpx.get", fake_get)

    provider._fetch_jwks(secondary_storage)

    assert captured_ttl["ttl"] == 7200


def test_fetch_user_info_accepts_schemeless_issuer() -> None:
    # Google docs require validators to accept iss="accounts.google.com" as
    # well as the canonical "https://accounts.google.com".
    provider = GoogleProvider(
        client_id="google-client-id",
        client_secret="google-client-secret",
    )
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_jwk = json.loads(RSAAlgorithm.to_jwk(private_key.public_key()))
    public_jwk["kid"] = "google-key-1"
    public_jwk["alg"] = "RS256"

    id_token = jwt.encode(
        {
            "iss": "accounts.google.com",
            "aud": "google-client-id",
            "sub": "google-user-123",
            "email": "user@example.com",
            "email_verified": True,
            "exp": datetime.now(tz=UTC) + timedelta(minutes=5),
            "iat": datetime.now(tz=UTC),
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "google-key-1"},
    )

    secondary_storage = MagicMock()
    secondary_storage.get.return_value = json.dumps({"keys": [public_jwk]})
    context = MagicMock()
    context.secondary_storage = secondary_storage

    user_info = provider.fetch_user_info(
        TokenResponse(
            token_type="Bearer",
            access_token="google-access-token",
            id_token=id_token,
        ),
        context,
    )

    assert user_info["id"] == "google-user-123"
