import json
import time
from concurrent.futures import ThreadPoolExecutor
from threading import Event, Lock
from typing import Any

import httpx
import jwt
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from cross_auth.social_providers.google import GoogleProvider
from cross_auth.social_providers.oauth import OAuth2Exception
from tests.conftest import MemoryStorage


@pytest.fixture(scope="module")
def signing_keys():
    return tuple(
        rsa.generate_private_key(public_exponent=65537, key_size=2048) for _ in range(2)
    )


@pytest.fixture
def cache_clock(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(time, "monotonic", lambda: now[0])
    return now


def _jwks(key: rsa.RSAPrivateKey, kid: str) -> dict[str, Any]:
    public_key = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    return {"keys": [{**public_key, "kid": kid}]}


def _token(provider: GoogleProvider, key: rsa.RSAPrivateKey, kid: str) -> str:
    return jwt.encode(
        {
            "iss": "https://accounts.google.com",
            "sub": "user",
            "aud": provider.client_id,
            "iat": int(time.time()) - 10,
            "exp": int(time.time()) + 300,
        },
        key,
        algorithm="RS256",
        headers={"kid": kid},
    )


def _provider(**kwargs: Any) -> GoogleProvider:
    return GoogleProvider(client_id="client", client_secret="secret", **kwargs)


@respx.mock
def test_custom_jwks_endpoints_do_not_share_keys_or_cooldowns(signing_keys):
    first = _provider(jwks_uri="https://first.example/jwks")
    second = _provider(jwks_uri="https://second.example/jwks")
    assert first.jwks_cache_key != second.jwks_cache_key
    assert first.jwks_cache_key != GoogleProvider.jwks_cache_key
    assert _provider(jwks_uri=first.jwks_uri).jwks_cache_key == first.jwks_cache_key
    assert _provider().jwks_cache_key == "google:jwks"
    assert _provider(jwks_uri=GoogleProvider.jwks_uri).jwks_cache_key == "google:jwks"

    storage = MemoryStorage()
    first_route = respx.get(first.jwks_uri).respond(
        200, json=_jwks(signing_keys[0], "key")
    )
    second_route = respx.get(second.jwks_uri).respond(
        200, json=_jwks(signing_keys[1], "key")
    )
    for provider, key in zip((first, second), signing_keys):
        assert (
            provider.validate_id_token(_token(provider, key, "key"), storage)["sub"]
            == "user"
        )
    assert first_route.call_count == second_route.call_count == 1

    third = _provider(jwks_uri="https://third.example/jwks")
    storage.set(third.jwks_cache_key, json.dumps(_jwks(signing_keys[0], "old")))
    third_route = respx.get(third.jwks_uri).respond(
        200, json=_jwks(signing_keys[1], "new")
    )
    assert (
        third.validate_id_token(_token(third, signing_keys[1], "new"), storage)["sub"]
        == "user"
    )
    assert third_route.call_count == 1


def test_endpoint_subclass_inherits_endpoint_aware_default_key():
    class LocalGoogleProvider(GoogleProvider):
        jwks_uri = "https://local.example/jwks"

    local = LocalGoogleProvider(client_id="client", client_secret="secret")
    assert local.jwks_cache_key == _provider(jwks_uri=local.jwks_uri).jwks_cache_key


@respx.mock
def test_explicit_jwks_cache_key_is_not_rewritten(signing_keys):
    class CustomGoogleProvider(GoogleProvider):
        jwks_cache_key = "application:google-keys"

    provider = CustomGoogleProvider(
        client_id="client",
        client_secret="secret",
        jwks_uri="https://local.example/jwks",
    )
    assert provider.jwks_cache_key == "application:google-keys"
    storage = MemoryStorage()
    storage.set("application:google-keys", json.dumps(_jwks(signing_keys[0], "key")))
    claims = provider.validate_id_token(
        _token(provider, signing_keys[0], "key"), storage
    )
    assert claims["sub"] == "user"
    assert not respx.calls


@respx.mock
def test_cached_key_needs_no_provider_request(signing_keys):
    provider = _provider()
    storage = MemoryStorage()
    storage.set(provider.jwks_cache_key, json.dumps(_jwks(signing_keys[0], "old")))

    assert (
        provider.validate_id_token(_token(provider, signing_keys[0], "old"), storage)[
            "sub"
        ]
        == "user"
    )
    assert not respx.calls


@pytest.mark.parametrize("separate_provider", [False, True])
@respx.mock
def test_concurrent_cold_fetch_does_not_reject_valid_tokens(
    signing_keys, separate_provider
):
    provider = _provider()
    second_provider = _provider() if separate_provider else provider
    storage = MemoryStorage()
    token = _token(provider, signing_keys[0], "key")
    first_started = Event()
    release_first = Event()
    request_lock = Lock()
    requests_started = 0

    def respond(request: httpx.Request) -> httpx.Response:
        nonlocal requests_started
        with request_lock:
            requests_started += 1
            first_request = requests_started == 1
        if first_request:
            first_started.set()
            assert release_first.wait(timeout=5)
        return httpx.Response(200, json=_jwks(signing_keys[0], "key"))

    route = respx.get(provider.jwks_uri).mock(side_effect=respond)
    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(provider.validate_id_token, token, storage)
        try:
            assert first_started.wait(timeout=5)
            second = executor.submit(second_provider.validate_id_token, token, storage)
            assert second.result(timeout=5)["sub"] == "user"
        finally:
            release_first.set()
        assert first.result(timeout=5)["sub"] == "user"
    assert route.call_count == 2


@pytest.mark.parametrize("warm_cache", [False, True])
@respx.mock
def test_reader_rechecks_cache_when_another_fetch_finishes(signing_keys, warm_cache):
    provider = _provider()
    cached = json.dumps(_jwks(signing_keys[0], "key"))
    first_cache_read = True

    class CompletingFetchStorage(MemoryStorage):
        def get(self, key: str) -> str | None:
            nonlocal first_cache_read
            value = super().get(key)
            if key == provider.jwks_cache_key and first_cache_read:
                # Another fetch commits after this reader's cache snapshot.
                first_cache_read = False
                self.set(key, cached)
                self.set(f"{key}:refetch-cooldown", "1", ttl=60)
            return value

    storage = CompletingFetchStorage()
    if warm_cache:
        storage.set(provider.jwks_cache_key, json.dumps(_jwks(signing_keys[1], "old")))
    claims = provider.validate_id_token(
        _token(provider, signing_keys[0], "key"), storage
    )
    assert claims["sub"] == "user"
    assert not respx.calls


@respx.mock
def test_cold_unknown_key_fetches_only_once_across_instances(signing_keys):
    provider = _provider()
    storage = MemoryStorage()
    route = respx.get(provider.jwks_uri).respond(
        200, json=_jwks(signing_keys[0], "old")
    )
    token = _token(provider, signing_keys[1], "unknown")

    for current in (provider, _provider()):
        with pytest.raises(OAuth2Exception, match="cooldown") as error:
            current.validate_id_token(token, storage)
        assert error.value.error == "invalid_token"
    assert route.call_count == 1


@respx.mock
def test_unknown_key_refreshes_cache_and_shares_expiring_cooldown(
    signing_keys, cache_clock
):
    provider = _provider()
    storage = MemoryStorage()
    storage.set(provider.jwks_cache_key, json.dumps(_jwks(signing_keys[0], "old")))
    rotated = _jwks(signing_keys[1], "new")
    route = respx.get(provider.jwks_uri).respond(200, json=rotated)

    assert (
        provider.validate_id_token(_token(provider, signing_keys[1], "new"), storage)[
            "sub"
        ]
        == "user"
    )
    cached = storage.get(provider.jwks_cache_key)
    assert cached is not None
    assert json.loads(cached) == rotated
    with pytest.raises(OAuth2Exception, match="Key old not found"):
        provider.validate_id_token(_token(provider, signing_keys[0], "old"), storage)
    missing = _token(provider, signing_keys[0], "unknown")
    with pytest.raises(OAuth2Exception, match="cooldown"):
        _provider().validate_id_token(missing, storage)
    assert route.call_count == 1

    cache_clock[0] += provider._JWKS_REFETCH_COOLDOWN + 1
    with pytest.raises(OAuth2Exception, match="Key unknown not found"):
        _provider().validate_id_token(missing, storage)
    assert route.call_count == 2
    assert (
        provider.validate_id_token(_token(provider, signing_keys[1], "new"), storage)[
            "sub"
        ]
        == "user"
    )
    assert route.call_count == 2


@respx.mock
def test_failed_cold_fetch_is_cooled_down_across_instances(signing_keys, cache_clock):
    provider = _provider()
    storage = MemoryStorage()
    route = respx.get(provider.jwks_uri).respond(503)
    token = _token(provider, signing_keys[0], "key")

    with pytest.raises(OAuth2Exception) as outage:
        provider.validate_id_token(token, storage)
    assert outage.value.error == "temporarily_unavailable"
    with pytest.raises(OAuth2Exception, match="cooldown") as cooled:
        _provider().validate_id_token(token, storage)
    # Still the provider's outage, not a bad token.
    assert cooled.value.error == "temporarily_unavailable"
    assert storage.get(provider.jwks_cache_key) is None
    assert route.call_count == 1

    cache_clock[0] += provider._JWKS_REFETCH_COOLDOWN + 1
    route.respond(200, json=_jwks(signing_keys[0], "key"))
    assert _provider().validate_id_token(token, storage)["sub"] == "user"
    assert route.call_count == 2


@pytest.mark.parametrize(
    "failure", ["status", "transport", "json", "shape", "key-shape", "rsa-key"]
)
@respx.mock
def test_failed_refresh_preserves_good_keys_and_cooldown(signing_keys, failure):
    provider = _provider()
    storage = MemoryStorage()
    cached = json.dumps(_jwks(signing_keys[0], "old"))
    storage.set(provider.jwks_cache_key, cached, ttl=3600)
    previous = storage.data[provider.jwks_cache_key]
    route = respx.get(provider.jwks_uri)
    if failure == "status":
        route.respond(503, json={"error": "unavailable"})
    elif failure == "transport":
        route.mock(side_effect=httpx.ReadTimeout("unavailable"))
    elif failure == "json":
        route.respond(200, text="not-json")
    elif failure == "shape":
        route.respond(200, json={"error": "missing keys"})
    elif failure == "key-shape":
        route.respond(200, json={"keys": ["not a key"]})
    else:
        route.respond(200, json={"keys": [{"kty": "RSA", "kid": "new"}]})

    with pytest.raises(OAuth2Exception):
        provider.validate_id_token(_token(provider, signing_keys[1], "new"), storage)
    assert storage.data[provider.jwks_cache_key] == previous
    assert (
        _provider().validate_id_token(
            _token(provider, signing_keys[0], "old"), storage
        )["sub"]
        == "user"
    )
    with pytest.raises(OAuth2Exception, match="cooldown"):
        _provider().validate_id_token(_token(provider, signing_keys[1], "new"), storage)
    assert route.call_count == 1
