import pytest
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
    return make_sqlite_engine()
