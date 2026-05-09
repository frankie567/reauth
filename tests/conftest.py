from collections.abc import AsyncGenerator

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine


@pytest.fixture
async def sqlalchemy_engine() -> AsyncGenerator[AsyncEngine]:
    """Fixture that provides an async SQLAlchemy engine for testing."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    try:
        yield engine
    finally:
        await engine.dispose()
