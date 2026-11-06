from __future__ import annotations

from collections.abc import Iterator

import pytest
import respx
from django.db import connections

from cross_auth.django.storage import DjangoAccountsStorage, DjangoSecondaryStorage

from .fake_google import FakeGoogle


@pytest.fixture
def storage() -> DjangoAccountsStorage:
    return DjangoAccountsStorage()


@pytest.fixture
def secondary() -> DjangoSecondaryStorage:
    return DjangoSecondaryStorage()


@pytest.fixture
def google() -> Iterator[FakeGoogle]:
    with respx.mock(assert_all_called=False) as router:
        fake = FakeGoogle(router)
        fake.install()
        yield fake


@pytest.fixture
def is_postgres() -> Iterator[bool]:
    yield connections["default"].vendor == "postgresql"
