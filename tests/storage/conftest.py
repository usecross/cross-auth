import os

import pytest
from sqlalchemy import event
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel, create_engine

from . import models  # noqa: F401 - registers the test tables on the metadata


def make_sqlite_engine():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    return engine


@pytest.fixture
def engine():
    engine = make_sqlite_engine()
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.fixture(scope="module")
def pg_engine():
    # SQLite coverage must still collect without PostgreSQL-only dependencies.
    pytest.importorskip("psycopg")
    postgres = pytest.importorskip("testcontainers.postgres")
    container = postgres.PostgresContainer("postgres:16-alpine", driver="psycopg")
    try:
        container.start()
    except Exception as exc:
        if os.environ.get("CI"):
            raise
        pytest.skip(f"Docker unavailable for testcontainers: {exc}")
    try:
        engine = create_engine(
            container.get_connection_url(),
            # A non-UTC connection exposes incorrect aware/naive binding.
            connect_args={"options": "-c TimeZone=America/New_York"},
        )
        try:
            SQLModel.metadata.create_all(engine)
            yield engine
        finally:
            engine.dispose()
    finally:
        container.stop()


@pytest.fixture(params=["sqlite", "postgresql"])
def signup_engine(request, tmp_path):
    """Independent connections for real transaction/concurrency contracts."""
    if request.param == "postgresql":
        yield request.getfixturevalue("pg_engine")
        return

    engine = create_engine(
        f"sqlite:///{tmp_path / 'signup.db'}",
        connect_args={"check_same_thread": False, "timeout": 10},
    )

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(connection, _record):
        connection.execute("PRAGMA foreign_keys=ON")

    try:
        SQLModel.metadata.create_all(engine)
        yield engine
    finally:
        engine.dispose()
