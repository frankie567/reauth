import os
import pathlib
from collections.abc import AsyncGenerator

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine


@pytest.fixture(
    params=os.environ.get("REAUTH_TEST_DATABASE", "postgresql,mysql,sqlite").split(",")
)
async def sqlalchemy_integration_engine(
    request: pytest.FixtureRequest, tmp_path: pathlib.Path
) -> AsyncGenerator[AsyncEngine]:
    """Provide an independent database for each SQLAlchemy integration test."""
    if request.param == "sqlite":
        engine = create_async_engine(
            f"sqlite+aiosqlite:///{tmp_path / 'reauth.db'}",
            connect_args={"autocommit": False},
        )
    else:
        variable = f"REAUTH_TEST_{request.param.upper()}_URL"
        url = os.environ.get(variable)
        if url is None:
            pytest.skip(f"Set {variable} to run {request.param} integration tests")
        engine = create_async_engine(url)
    try:
        yield engine
    finally:
        await engine.dispose()


@pytest.fixture
async def sqlalchemy_engine() -> AsyncGenerator[AsyncEngine]:
    """Fixture that provides an async SQLAlchemy engine for testing."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    try:
        yield engine
    finally:
        await engine.dispose()
