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

from reauth.factors.oauth2.base import OAuth2Factor
from reauth.factors.oauth2.state import OAuth2State, OAuth2StateService

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
            .values(**dict(oauth2_state.__dict__))
            .returning(oauth2_state_table.c.id)
        )
        return result.scalar_one()

    async def delete(self, oauth2_state: OAuth2State) -> None:
        """Delete OAuth2 state from the database."""
        await self.connection.execute(
            delete(oauth2_state_table).where(oauth2_state_table.c.id == oauth2_state.id)
        )


class ConcreteOAuth2Factor(OAuth2Factor):
    """Concrete implementation for testing."""

    async def get_enrollment(self, identity_id: int) -> None:
        """Mock implementation for testing."""
        return None

    async def get_authorization_url(
        self,
        *,
        redirect_uri: str,
        scope: list[str] | None = None,
        state: str,
        code_challenge: str | None = None,
        code_challenge_method: str | None = None,
        nonce: str | None = None,
        extra: dict[str, str] | None = None,
    ) -> str:
        return f"https://provider.example.com/auth?state={state}"


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
        hash_secret="test-secret",
        lifetime=datetime.timedelta(minutes=10),
    )


@pytest.fixture
def oauth2_factor(
    oauth2_state_service: SQLAlchemyOAuth2StateService,
) -> ConcreteOAuth2Factor:
    """Fixture providing a concrete OAuth2 factor for testing."""
    return ConcreteOAuth2Factor(
        identifier="test",
        client_id="test-client-id",
        state_service=oauth2_state_service,
    )


@pytest.mark.anyio
class TestOAuth2FactorStart:
    async def test_returns_url_token_and_state(
        self, oauth2_factor: ConcreteOAuth2Factor
    ) -> None:
        """start() returns authorization URL, state token, and state."""
        authorization_url, state_token, oauth2_state = await oauth2_factor.start(
            provider="google",
            redirect_uri="https://example.com/callback",
        )

        assert isinstance(authorization_url, str)
        assert authorization_url.startswith("https://provider.example.com/auth?state=")
        assert isinstance(state_token, str)
        assert len(state_token) > 0
        assert state_token.startswith("reauth_oauth2_")
        assert isinstance(oauth2_state, OAuth2State)
        assert oauth2_state.provider == "google"

    async def test_generates_pkce_with_s256(
        self, oauth2_factor: ConcreteOAuth2Factor
    ) -> None:
        """start() generates PKCE code_verifier when S256 is specified."""
        _, _, oauth2_state = await oauth2_factor.start(
            provider="google",
            redirect_uri="https://example.com/callback",
            code_challenge_method="S256",
        )

        assert oauth2_state.code_verifier is not None
