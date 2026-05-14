import dataclasses
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
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from reauth.factors.oauth2.state import (
    ExpiredStateException,
    InvalidStateException,
    OAuth2State,
    OAuth2StateService,
)

sqlalchemy_meta = MetaData()
oauth2_state_table = Table(
    "oauth2_states",
    sqlalchemy_meta,
    Column("id", Integer, primary_key=True),
    Column("state_hash", String(64), nullable=False, unique=True),
    Column("provider", String(64), nullable=False),
    Column("code_verifier", String(128), nullable=True),
    Column("nonce", String(128), nullable=True),
    Column("redirect_uri", String(512), nullable=False),
    Column("identity_id", BigInteger, nullable=True),
    Column("scope", JSON, nullable=True),
    Column("expires_at", BigInteger, nullable=False),
)


class SQLAlchemyOAuth2StateService(OAuth2StateService):
    """Concrete implementation of OAuth2StateService using SQLAlchemy."""

    def __init__(
        self,
        connection: AsyncConnection,
        *,
        hash_secret: str = "test-secret",
        lifetime: datetime.timedelta = datetime.timedelta(minutes=10),
    ) -> None:
        self.connection = connection
        super().__init__(hash_secret=hash_secret, lifetime=lifetime)

    async def get_by_state_hash(self, state_hash: str) -> OAuth2State | None:
        """Retrieve OAuth2 state by its hash from the database."""
        result = await self.connection.execute(
            select(oauth2_state_table).where(
                oauth2_state_table.c.state_hash == state_hash
            )
        )
        row = result.fetchone()
        if row is None:
            return None
        return OAuth2State(**row._asdict())

    async def insert(self, oauth2_state: OAuth2State) -> int:
        """Insert OAuth2 state into the database."""
        result = await self.connection.execute(
            insert(oauth2_state_table)
            .values(**dataclasses.asdict(oauth2_state))
            .returning(oauth2_state_table.c.id)
        )
        return result.scalar_one()

    async def delete(self, oauth2_state: OAuth2State) -> None:
        """Delete OAuth2 state from the database."""
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
    """Fixture that provides an instance of SQLAlchemyOAuth2StateService."""
    return SQLAlchemyOAuth2StateService(
        connection=sqlalchemy_connection,
        hash_secret="test-secret",
        lifetime=datetime.timedelta(minutes=10),
    )


@pytest.mark.anyio
class TestOAuth2StateCreate:
    async def test_returns_state_token_and_state(
        self, oauth2_state_service: SQLAlchemyOAuth2StateService
    ) -> None:
        state_token, oauth2_state = await oauth2_state_service.create(
            provider="google",
            redirect_uri="https://example.com/callback",
            code_verifier="test_verifier",
        )

        assert isinstance(state_token, str)
        assert len(state_token) > 0
        assert isinstance(oauth2_state, OAuth2State)
        assert oauth2_state.id is not None
        assert oauth2_state.provider == "google"
        assert oauth2_state.code_verifier == "test_verifier"
        assert oauth2_state.redirect_uri == "https://example.com/callback"
        assert oauth2_state.nonce is None
        assert oauth2_state.identity_id is None
        assert oauth2_state.expires_at > 0

    async def test_with_nonce(
        self, oauth2_state_service: SQLAlchemyOAuth2StateService
    ) -> None:
        _, oauth2_state = await oauth2_state_service.create(
            provider="github",
            redirect_uri="https://example.com/callback",
            nonce="test_nonce",
        )

        assert oauth2_state.nonce == "test_nonce"

    async def test_with_identity_id(
        self, oauth2_state_service: SQLAlchemyOAuth2StateService
    ) -> None:
        _, oauth2_state = await oauth2_state_service.create(
            provider="google",
            redirect_uri="https://example.com/callback",
            identity_id=123,
        )

        assert oauth2_state.identity_id == 123

    async def test_state_token_has_prefix(
        self, oauth2_state_service: SQLAlchemyOAuth2StateService
    ) -> None:
        state_token, _ = await oauth2_state_service.create(
            provider="google",
            redirect_uri="https://example.com/callback",
        )

        assert state_token.startswith("reauth_oauth2_")

    async def test_without_code_verifier(
        self, oauth2_state_service: SQLAlchemyOAuth2StateService
    ) -> None:
        _, oauth2_state = await oauth2_state_service.create(
            provider="google",
            redirect_uri="https://example.com/callback",
        )

        assert oauth2_state.code_verifier is None

    async def test_with_scope(
        self, oauth2_state_service: SQLAlchemyOAuth2StateService
    ) -> None:
        _, oauth2_state = await oauth2_state_service.create(
            provider="google",
            redirect_uri="https://example.com/callback",
            scope=["read", "write", "profile"],
        )

        assert oauth2_state.scope == ["read", "write", "profile"]

    async def test_without_scope(
        self, oauth2_state_service: SQLAlchemyOAuth2StateService
    ) -> None:
        _, oauth2_state = await oauth2_state_service.create(
            provider="google",
            redirect_uri="https://example.com/callback",
        )

        assert oauth2_state.scope is None


@pytest.mark.anyio
class TestOAuth2StateConsume:
    async def test_consume_valid_state(
        self, oauth2_state_service: SQLAlchemyOAuth2StateService
    ) -> None:
        state_token, expected_state = await oauth2_state_service.create(
            provider="google",
            redirect_uri="https://example.com/callback",
            code_verifier="test_verifier",
        )

        oauth2_state = await oauth2_state_service.consume(state_token)

        assert oauth2_state.id == expected_state.id
        assert oauth2_state.provider == "google"
        assert oauth2_state.code_verifier == "test_verifier"

    async def test_consume_invalid_state(
        self, oauth2_state_service: SQLAlchemyOAuth2StateService
    ) -> None:
        with pytest.raises(InvalidStateException):
            await oauth2_state_service.consume("invalid_state_token")

    async def test_consume_deletes_state(
        self, oauth2_state_service: SQLAlchemyOAuth2StateService
    ) -> None:
        state_token, _ = await oauth2_state_service.create(
            provider="google",
            redirect_uri="https://example.com/callback",
        )

        # First consume should succeed
        oauth2_state = await oauth2_state_service.consume(state_token)
        assert oauth2_state is not None

        # Second consume with same token should fail (already deleted)
        with pytest.raises(InvalidStateException):
            await oauth2_state_service.consume(state_token)

    async def test_consume_expired_state(
        self, sqlalchemy_connection: AsyncConnection
    ) -> None:
        service = SQLAlchemyOAuth2StateService(
            connection=sqlalchemy_connection,
            hash_secret="test-secret",
            lifetime=datetime.timedelta(seconds=0),  # Expires immediately
        )

        state_token, _ = await service.create(
            provider="google",
            redirect_uri="https://example.com/callback",
        )

        with pytest.raises(ExpiredStateException):
            await service.consume(state_token)
