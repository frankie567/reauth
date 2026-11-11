import datetime
from collections.abc import AsyncGenerator

import pytest
from sqlalchemy import MetaData
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from reauth.integrations.sqlalchemy import (
    SQLAlchemyOAuth2StateService,
    create_oauth2_enrollment_table,
    create_oauth2_state_table,
)
from reauth.tokens import ChecksummedTokenProvider, HMACTokenVerifier

sqlalchemy_meta = MetaData()
oauth2_state_table = create_oauth2_state_table(sqlalchemy_meta)
oauth2_enrollment_table = create_oauth2_enrollment_table(sqlalchemy_meta)


@pytest.fixture
async def sqlalchemy_connection(
    sqlalchemy_integration_engine: AsyncEngine,
) -> AsyncGenerator[AsyncConnection]:
    """Fixture that creates tables and provides a connection for testing."""
    async with sqlalchemy_integration_engine.begin() as conn:
        await conn.run_sync(sqlalchemy_meta.create_all)
        yield conn
        await conn.run_sync(sqlalchemy_meta.drop_all)


@pytest.fixture
def oauth2_state_service(
    sqlalchemy_connection: AsyncConnection,
) -> SQLAlchemyOAuth2StateService:
    """Fixture providing an instance of SQLAlchemyOAuth2StateService."""
    return SQLAlchemyOAuth2StateService(
        connection=sqlalchemy_connection,
        table=oauth2_state_table,
        token_provider=ChecksummedTokenProvider(
            prefix="reauth_oauth2_",
            verifier=HMACTokenVerifier(current_key_id="test", keys={"test": b"t" * 32}),
        ),
        lifetime=datetime.timedelta(minutes=10),
    )
