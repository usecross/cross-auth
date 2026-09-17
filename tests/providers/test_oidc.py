"""Validate real signed OIDC claims against a cached provider key."""

import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from cross_auth.social_providers.google import GoogleProvider
from cross_auth.social_providers.oauth import OAuth2Exception
from tests.conftest import MemoryStorage


@pytest.fixture(scope="module")
def signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def validate(signing_key):
    provider = GoogleProvider(client_id="web-client", client_secret="secret")
    public_key = json.loads(RSAAlgorithm.to_jwk(signing_key.public_key()))
    public_key["kid"] = "test-key"
    storage = MemoryStorage()
    storage.set(provider.jwks_cache_key, json.dumps({"keys": [public_key]}))

    def validate_claims(claims):
        token = jwt.api_jws.encode(
            json.dumps(claims).encode(),
            signing_key,
            algorithm="RS256",
            headers={"kid": "test-key"},
        )
        return provider.validate_id_token(token, storage)

    return validate_claims


@pytest.fixture
def claims():
    now = int(time.time())
    return {
        "iss": "https://accounts.google.com",
        "aud": "web-client",
        "sub": "google-user",
        "iat": now - 10,
        "exp": now + 300,
    }


@pytest.mark.parametrize("field", ["iss", "aud", "sub", "exp", "iat"])
def test_required_claims_cannot_be_omitted(validate, claims, field):
    del claims[field]

    with pytest.raises(OAuth2Exception, match="id_token") as error:
        validate(claims)

    assert error.value.error == "invalid_token"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("sub", ""),
        ("sub", 123),
        ("sub", []),
        ("iss", ["https://accounts.google.com"]),
        ("aud", 123),
        ("aud", ["web-client", 123]),
        *[
            (field, value)
            for field in ("exp", "iat", "nbf")
            for value in (
                None,
                True,
                False,
                [],
                {},
                "2000000000",
                float("inf"),
                float("nan"),
            )
        ],
    ],
)
def test_invalid_claim_types_are_invalid_tokens(validate, claims, field, value):
    claims[field] = value

    with pytest.raises(OAuth2Exception, match="id_token") as error:
        validate(claims)

    assert error.value.error == "invalid_token"


@pytest.mark.parametrize(
    ("field", "value", "description"),
    [
        ("iss", "https://other.example", "issuer mismatch"),
        ("aud", "other-client", "audience mismatch"),
        ("exp", 1, "has expired"),
        ("iat", 4000000000, "not yet valid"),
    ],
)
def test_claim_validation_preserves_errors(validate, claims, field, value, description):
    claims[field] = value

    with pytest.raises(OAuth2Exception, match=description) as error:
        validate(claims)

    assert error.value.error == "invalid_token"


def test_numeric_fractional_dates_are_supported(validate, claims):
    claims["iat"] += 0.5
    claims["exp"] += 0.5

    assert validate(claims)["sub"] == "google-user"


def test_google_native_presenter_can_differ_from_web_audience(validate, claims):
    claims["azp"] = "android-client"

    assert validate(claims)["azp"] == "android-client"


@pytest.mark.parametrize("token", ["not-a-jwt", "a.b.c", "e30.e30.invalid", "\ud800"])
def test_malformed_jwt_header_is_invalid_token(token):
    provider = GoogleProvider(client_id="web-client", client_secret="secret")

    with pytest.raises(OAuth2Exception, match="id_token") as error:
        provider.validate_id_token(token, MemoryStorage())

    assert error.value.error == "invalid_token"


@pytest.mark.parametrize("field", ["iat", "nbf"])
def test_past_numeric_string_is_not_a_numeric_date(validate, claims, field):
    claims[field] = "1"

    with pytest.raises(
        OAuth2Exception, match=f"{field} must be a finite number"
    ) as error:
        validate(claims)

    assert error.value.error == "invalid_token"


def test_string_issuer_requires_exact_match(validate, claims, monkeypatch):
    monkeypatch.setattr(GoogleProvider, "issuer", "https://accounts.google.com")
    claims["iss"] = "accounts.google.com"

    with pytest.raises(OAuth2Exception, match="issuer mismatch"):
        validate(claims)
