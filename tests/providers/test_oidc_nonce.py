import hashlib
import json
import time
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from cross_auth.models.oauth_token_response import TokenResponse
from cross_auth.social_providers.google import GoogleProvider
from cross_auth.social_providers.oauth import OAuth2Exception, OAuth2Provider


@pytest.mark.parametrize("nonce", ["attempt-nonce", None])
def test_oidc_nonce_cannot_come_from_extra_parameters(nonce):
    extras = {"nonce": "static-nonce", "prompt": "consent"}
    provider = GoogleProvider(
        client_id="client", client_secret="secret", extra_authorization_params=extras
    )

    url = provider.build_authorization_url(
        state="state",
        redirect_uri="https://app.example/callback",
        provider_data={"nonce": nonce} if nonce is not None else None,
    )
    params = parse_qs(urlparse(url).query)

    assert params.get("nonce") == ([nonce] if nonce is not None else None)
    assert params["prompt"] == ["consent"]
    assert extras["nonce"] == "static-nonce"


@pytest.fixture(scope="module")
def signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.mark.parametrize(
    "claim",
    [
        "attempt-nonce",
        None,
        "",
        "other-attempt",
        123,
        ["attempt-nonce"],
        hashlib.sha256(b"attempt-nonce").hexdigest(),
    ],
)
def test_browser_nonce_must_match_signed_claim_exactly(signing_key, claim, context):
    provider = GoogleProvider(client_id="client", client_secret="secret")
    key = json.loads(RSAAlgorithm.to_jwk(signing_key.public_key()))
    key["kid"] = "key"
    storage = context.secondary_storage
    storage.set(provider.jwks_cache_key, json.dumps({"keys": [key]}))
    now = int(time.time())
    claims = {
        "iss": "https://accounts.google.com",
        "aud": "client",
        "sub": "user",
        "iat": now - 10,
        "exp": now + 300,
    }
    if claim is not None:
        claims["nonce"] = claim
    token = jwt.encode(claims, signing_key, algorithm="RS256", headers={"kid": "key"})
    response = TokenResponse(token_type="Bearer", access_token="access", id_token=token)

    if claim == "attempt-nonce":
        assert (
            provider.fetch_user_info(
                response, context, provider_data={"nonce": "attempt-nonce"}
            )["id"]
            == "user"
        )
    else:
        with pytest.raises(OAuth2Exception, match="nonce mismatch") as error:
            provider.fetch_user_info(
                response, context, provider_data={"nonce": "attempt-nonce"}
            )

        assert error.value.error == "invalid_token"


def test_oauth_extra_nonce_remains_provider_specific():
    class Provider(OAuth2Provider):
        id = "oauth"
        authorization_endpoint = "https://provider.example/authorize"
        scopes = []

    provider = Provider(
        client_id="client",
        client_secret="secret",
        extra_authorization_params={"nonce": "provider-specific-value"},
    )

    url = provider.build_authorization_url(
        state="state", redirect_uri="https://app.example/callback"
    )

    assert parse_qs(urlparse(url).query)["nonce"] == ["provider-specific-value"]


def test_private_authorization_data_is_not_added_to_url():
    provider = GoogleProvider(client_id="client", client_secret="secret")
    data = {**provider.get_authorization_data(), "private_value": "server-only"}

    url = provider.build_authorization_url(
        state="state", redirect_uri="https://app.example/callback", provider_data=data
    )
    params = parse_qs(urlparse(url).query)

    assert params["nonce"] == [data["nonce"]]
    assert "private_value" not in params
    assert "server-only" not in url
