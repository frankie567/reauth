import datetime
from collections.abc import AsyncGenerator

import pytest
from sqlalchemy import (
    JSON,
    BigInteger,
    Column,
    Integer,
    MetaData,
    String,
    Table,
    delete,
    insert,
    select,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from reauth.factors.oauth2.state import (
    OAuth2State,
    OAuth2StateService,
)
from reauth.tokens import (
    ChecksummedTokenProvider,
    HMACTokenVerifier,
    TokenIdentifierCollision,
    TokenProvider,
)

sqlalchemy_meta = MetaData()

oauth2_state_table = Table(
    "oauth2_states",
    sqlalchemy_meta,
    Column("id", Integer, primary_key=True),
    Column("token_identifier", String(16), nullable=False, unique=True),
    Column("token_verifier", String, nullable=False),
    Column("provider", String(64), nullable=False),
    Column("code_verifier", String(128), nullable=True),
    Column("nonce", String(128), nullable=True),
    Column("redirect_uri", String(512), nullable=False),
    Column("identity_id", BigInteger, nullable=True),
    Column("scope", JSON, nullable=True),
    Column("expires_at", BigInteger, nullable=False),
    Column("context", JSON, nullable=True),
)

# Enrollment table for testing
oauth2_enrollment_table = Table(
    "oauth2_enrollments",
    sqlalchemy_meta,
    Column("id", Integer, primary_key=True),
    Column("identity_id", BigInteger, nullable=False),
    Column("provider", String(64), nullable=False),
    Column("account_id", String(128), nullable=False),
    Column("access_token", String(512), nullable=False),
    Column("expires_at", BigInteger, nullable=True),
    Column("refresh_token", String(512), nullable=True),
    Column("refresh_token_expires_at", BigInteger, nullable=True),
    Column("scope", JSON, nullable=True),
    Column("id_token", String(1024), nullable=True),
)


class SQLAlchemyOAuth2StateService(OAuth2StateService):
    """Concrete implementation of OAuth2StateService using SQLAlchemy."""

    def __init__(
        self,
        connection: AsyncConnection,
        *,
        token_provider: TokenProvider | None = None,
        lifetime: datetime.timedelta = datetime.timedelta(minutes=10),
    ) -> None:
        self.connection = connection
        super().__init__(
            token_provider=token_provider
            or ChecksummedTokenProvider(
                prefix="reauth_oauth2_",
                verifier=HMACTokenVerifier(
                    current_key_id="test", keys={"test": b"t" * 32}
                ),
            ),
            lifetime=lifetime,
        )

    async def get_by_token_identifier(
        self, token_identifier: str
    ) -> OAuth2State | None:
        """Retrieve OAuth2 state by its identifier from the database."""
        result = await self.connection.execute(
            select(oauth2_state_table).where(
                oauth2_state_table.c.token_identifier == token_identifier
            )
        )
        row = result.fetchone()
        if row is None:
            return None
        return OAuth2State(**row._asdict())

    async def insert(self, oauth2_state: OAuth2State) -> int:
        """Insert OAuth2 state into the database."""
        try:
            async with self.connection.begin_nested():
                result = await self.connection.execute(
                    insert(oauth2_state_table)
                    .values(**dict(oauth2_state.__dict__))
                    .returning(oauth2_state_table.c.id)
                )
                return result.scalar_one()
        except IntegrityError as error:
            raise TokenIdentifierCollision() from error

    async def delete(self, oauth2_state: OAuth2State) -> None:
        await self.connection.execute(
            delete(oauth2_state_table).where(oauth2_state_table.c.id == oauth2_state.id)
        )


@pytest.fixture
async def sqlalchemy_connection(
    sqlalchemy_engine: AsyncEngine,
) -> AsyncGenerator[AsyncConnection]:
    """Fixture that creates tables and provides a connection for testing."""
    async with sqlalchemy_engine.begin() as conn:
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
        lifetime=datetime.timedelta(minutes=10),
    )
