import dataclasses
import datetime
from collections.abc import AsyncGenerator

import pytest
from sqlalchemy import MetaData, insert
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from reauth.factors.oauth2.state import OAuth2State
from reauth.integrations.sqlalchemy.oauth2 import create_oauth2_enrollment_table
from reauth.integrations.sqlalchemy.oauth2_state import (
    SQLAlchemyOAuth2StateService,
    create_oauth2_state_table,
)
from reauth.timestamp import get_current_timestamp
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


@pytest.fixture
async def state_data(
    oauth2_state_service: SQLAlchemyOAuth2StateService,
) -> tuple[str, OAuth2State]:
    generated = await oauth2_state_service.token_provider.generate()
    state = OAuth2State(
        id=42,
        token_identifier=generated.identifier,
        token_verifier=generated.verifier,
        provider="provider",
        redirect_uri="https://example.com/callback",
        code_verifier="test_verifier",
        nonce=None,
        identity_id=None,
        scope=None,
        expires_at=get_current_timestamp() + 3600,
        context={"auth_session_id": 789, "custom_data": "test"},
    )
    await oauth2_state_service.connection.execute(
        insert(oauth2_state_table).values(**dataclasses.asdict(state))
    )
    return generated.token, state
