import asyncio

import pytest

from cross_auth import HookRegistration, HookRegistry

pytestmark = pytest.mark.asyncio


class DummyProvider:
    id = "dummy"


async def test_hooks_run_in_priority_order() -> None:
    calls: list[str] = []

    def low_priority_hook(*, user_info, access_token, provider):
        calls.append("low")

    def high_priority_hook_1(*, user_info, access_token, provider):
        calls.append("high-1")

    def high_priority_hook_2(*, user_info, access_token, provider):
        calls.append("high-2")

    registry = HookRegistry(
        hooks={
            "after_user_info": [
                HookRegistration(callback=low_priority_hook, priority=0),
                HookRegistration(callback=high_priority_hook_1, priority=10),
                HookRegistration(callback=high_priority_hook_2, priority=10),
            ]
        }
    )

    await registry.run(
        "after_user_info",
        user_info={"email": "user@example.com", "id": "u1", "email_verified": True},
        access_token="token",
        provider=DummyProvider(),
    )

    assert calls == ["high-1", "high-2", "low"]


async def test_hook_payload_is_read_only() -> None:
    mutation_error: Exception | None = None

    def hook(*, user_info, access_token, provider):
        nonlocal mutation_error

        try:
            user_info["email"] = "mutated@example.com"
        except Exception as e:
            mutation_error = e

    registry = HookRegistry(hooks={"after_user_info": [hook]})

    await registry.run(
        "after_user_info",
        user_info={"email": "user@example.com", "id": "u1", "email_verified": True},
        access_token="token",
        provider=DummyProvider(),
    )

    assert isinstance(mutation_error, TypeError)


async def test_strict_mode_raises_by_default() -> None:
    def failing_hook(*, user_info, access_token, provider):
        raise RuntimeError("failed")

    registry = HookRegistry(hooks={"after_user_info": [failing_hook]})

    with pytest.raises(RuntimeError):
        await registry.run(
            "after_user_info",
            user_info={"email": "user@example.com", "id": "u1", "email_verified": True},
            access_token="token",
            provider=DummyProvider(),
        )


async def test_robust_mode_ignores_errors_and_continues() -> None:
    calls: list[str] = []

    def failing_hook(*, user_info, access_token, provider):
        raise RuntimeError("failed")

    def succeeding_hook(*, user_info, access_token, provider):
        calls.append("ok")

    registry = HookRegistry(
        hooks={"after_user_info": [failing_hook, succeeding_hook]},
        settings={"mode_by_event": {"after_user_info": "robust"}},
    )

    await registry.run(
        "after_user_info",
        user_info={"email": "user@example.com", "id": "u1", "email_verified": True},
        access_token="token",
        provider=DummyProvider(),
    )

    assert calls == ["ok"]


async def test_hook_timeout_raises_in_strict_mode() -> None:
    async def slow_hook(*, user_info, access_token, provider):
        await asyncio.sleep(0.05)

    registry = HookRegistry(
        hooks={
            "after_user_info": [
                HookRegistration(
                    callback=slow_hook,
                    timeout_seconds=0.001,
                )
            ]
        }
    )

    with pytest.raises(TimeoutError):
        await registry.run(
            "after_user_info",
            user_info={"email": "user@example.com", "id": "u1", "email_verified": True},
            access_token="token",
            provider=DummyProvider(),
        )


async def test_hook_timeout_can_be_robust() -> None:
    calls: list[str] = []

    async def slow_hook(*, user_info, access_token, provider):
        await asyncio.sleep(0.05)

    def succeeding_hook(*, user_info, access_token, provider):
        calls.append("ok")

    registry = HookRegistry(
        hooks={
            "after_user_info": [
                HookRegistration(
                    callback=slow_hook,
                    timeout_seconds=0.001,
                    mode="robust",
                ),
                succeeding_hook,
            ]
        }
    )

    await registry.run(
        "after_user_info",
        user_info={"email": "user@example.com", "id": "u1", "email_verified": True},
        access_token="token",
        provider=DummyProvider(),
    )

    assert calls == ["ok"]


async def test_hook_registration_metadata_defaults() -> None:
    def hook(*, user_info, access_token, provider):
        return None

    registration = HookRegistration(callback=hook)

    assert registration.label == "hook"
    assert isinstance(registration.origin, str)
    assert registration.origin != ""


async def test_hook_registration_validates_timeout() -> None:
    def hook(*, user_info, access_token, provider):
        return None

    with pytest.raises(ValueError):
        HookRegistration(callback=hook, timeout_seconds=0)
