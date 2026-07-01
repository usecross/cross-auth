from typing import cast

import pytest
from redis import Redis

from cross_auth.storage.redis import RedisStorage

RedisValue = bytes | str | None


class FakeRedis:
    """Minimal redis-py-like client backed by a dict.

    ``decode_responses`` mirrors the real client: when False (default) reads
    return ``bytes``; when True they return ``str``.
    """

    def __init__(self, *, decode_responses: bool = False):
        self.data: dict[str, bytes] = {}
        self.decode_responses = decode_responses

    def _encode(self, value: str) -> bytes:
        return value.encode()

    def _read(self, raw: bytes | None) -> RedisValue:
        if raw is None:
            return None
        return raw.decode() if self.decode_responses else raw

    def set(self, name: str, value: str, ex: int | None = None) -> None:
        self.data[name] = self._encode(value)
        self.last_ex = ex

    def get(self, name: str) -> RedisValue:
        return self._read(self.data.get(name))

    def getdel(self, name: str) -> RedisValue:
        value = self.get(name)
        self.delete(name)
        return value

    def delete(self, *names: str) -> int:
        removed = 0
        for name in names:
            if name in self.data:
                del self.data[name]
                removed += 1
        return removed


def _typed(client: FakeRedis) -> Redis:
    return cast(Redis, client)


def test_set_passes_value_and_ttl():
    client = FakeRedis()
    storage = RedisStorage(_typed(client))

    storage.set("k", "v", ttl=42)

    assert client.get("k") == b"v"
    assert client.last_ex == 42


def test_set_without_ttl():
    client = FakeRedis()
    storage = RedisStorage(_typed(client))

    storage.set("k", "v")

    assert client.last_ex is None


def test_set_with_non_positive_ttl_deletes_the_key():
    # Redis rejects EX <= 0; an already-expired value must just not exist.
    client = FakeRedis()
    storage = RedisStorage(_typed(client))
    storage.set("k", "v")

    storage.set("k", "v2", ttl=0)
    assert storage.get("k") is None

    storage.set("other", "v", ttl=-5)
    assert storage.get("other") is None


def test_get_decodes_bytes():
    client = FakeRedis(decode_responses=False)
    storage = RedisStorage(_typed(client))
    storage.set("k", "v")

    assert storage.get("k") == "v"


def test_get_handles_already_decoded_str():
    client = FakeRedis(decode_responses=True)
    storage = RedisStorage(_typed(client))
    storage.set("k", "v")

    assert storage.get("k") == "v"


def test_get_missing_returns_none():
    storage = RedisStorage(_typed(FakeRedis()))

    assert storage.get("missing") is None


def test_delete():
    client = FakeRedis()
    storage = RedisStorage(_typed(client))
    storage.set("k", "v")

    storage.delete("k")

    assert storage.get("k") is None


def test_pop_uses_getdel():
    client = FakeRedis()
    storage = RedisStorage(_typed(client))
    storage.set("k", "v")

    assert storage.pop("k") == "v"
    assert storage.get("k") is None


def test_pop_missing_returns_none():
    storage = RedisStorage(_typed(FakeRedis()))

    assert storage.pop("missing") is None


def test_pop_handles_already_decoded_str():
    client = FakeRedis(decode_responses=True)
    storage = RedisStorage(_typed(client))
    storage.set("k", "v")

    assert storage.pop("k") == "v"
    assert storage.get("k") is None


def test_constructor_rejects_client_without_getdel():
    # redis-py < 4.2 (or any client that doesn't expose GETDEL) would raise
    # AttributeError on the first pop() call, mid-OAuth-callback — catch it
    # at construction instead.
    class NoGetDel:
        def get(self, name: str) -> RedisValue:
            return None

    with pytest.raises(TypeError, match="getdel"):
        RedisStorage(cast(Redis, NoGetDel()))


def test_constructor_rejects_async_client():
    # An async client (e.g. redis.asyncio.Redis) would make every method
    # return an unawaited coroutine instead of doing anything — set() would
    # silently store nothing.
    class AsyncRedis:
        def getdel(self, name: str) -> RedisValue:
            return None

        async def get(self, name: str) -> RedisValue:
            return None

    with pytest.raises(TypeError, match="synchronous"):
        RedisStorage(cast(Redis, AsyncRedis()))
