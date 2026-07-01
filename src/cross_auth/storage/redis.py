from __future__ import annotations

import inspect
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from redis import Redis

RedisValue = bytes | str | None


def _decode(value: RedisValue) -> str | None:
    """Normalize a redis response to ``str | None``.

    Default clients return ``bytes``; clients created with
    ``decode_responses=True`` already return ``str``.
    """
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.decode()
    return value


class RedisStorage:
    """Store transient auth data (OAuth, PKCE, verification, reset) in Redis.

    Pass an existing redis client::

        import redis
        from cross_auth.storage.redis import RedisStorage

        storage = RedisStorage(redis.Redis.from_url("redis://localhost:6379"))

    Requires a synchronous client (not ``redis.asyncio.Redis`` — every method
    would silently return an unawaited coroutine instead of doing anything)
    with ``GETDEL`` support: a Redis server >= 6.2 and redis-py >= 4.2
    (``pop`` uses the ``GETDEL`` command).

    The client is fixed at construction. To point tests elsewhere, construct
    a new ``RedisStorage`` with a different client rather than patching the
    settings the client was built from.
    """

    def __init__(self, client: Redis):
        if not callable(getattr(client, "getdel", None)):
            raise TypeError(
                f"{type(self).__name__} requires a Redis client with GETDEL "
                f"support (redis-py 4.2 or newer) — pop() calls "
                f"client.getdel(), which {type(client).__name__!r} does not "
                f"have."
            )
        # A synchronous client's `get` returns a value directly; an async
        # client's does too (it just hands back the coroutine created by its
        # own async execute_command), so `get` itself doesn't look like a
        # coroutine function. Check execute_command as well, since that one
        # is genuinely `async def` on an async client.
        get = getattr(client, "get", None)
        execute_command = getattr(client, "execute_command", None)
        if inspect.iscoroutinefunction(get) or inspect.iscoroutinefunction(
            execute_command
        ):
            raise TypeError(
                f"{type(self).__name__} requires a synchronous Redis client "
                f"(e.g. redis.Redis), not an async one like "
                f"{type(client).__name__!r} — every method would return an "
                f"unawaited coroutine instead of a value."
            )
        self._client = client

    def set(self, key: str, value: str, ttl: int | None = None) -> None:
        if ttl is not None and ttl <= 0:
            # Already expired; Redis rejects EX <= 0 with an error.
            self._client.delete(key)
            return
        self._client.set(key, value, ex=ttl)

    def get(self, key: str) -> str | None:
        return _decode(self._client.get(key))

    def delete(self, key: str) -> None:
        self._client.delete(key)

    def pop(self, key: str) -> str | None:
        """Atomically get and delete a key. Returns ``None`` if it is missing.

        Uses Redis ``GETDEL``, available on server 6.2 and newer.
        """
        return _decode(self._client.getdel(key))
