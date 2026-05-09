import dataclasses
import datetime
from collections.abc import AsyncGenerator

import pytest
from sqlalchemy import (
    Column,
    Integer,
    MetaData,
    String,
    Table,
    insert,
    select,
    update,
)
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from reauth.authentication_session import (
    AuthenticationSession,
    AuthenticationSessionService,
    ExpiredSessionException,
    InvalidSessionTokenException,
)
from reauth.crypto import generate_token_hash_pair, get_token_hash

sqlalchemy_meta = MetaData()
authentication_session_table = Table(
    "authentication_sessions",
    sqlalchemy_meta,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("token_hash", String(255), nullable=False),
    Column("expires_at", Integer, nullable=False),
    Column("identity_id", Integer, nullable=True),
)


class SQLAlchemyAuthenticationSession(AuthenticationSessionService):
    """Concrete implementation of AuthenticationSessionService using SQLAlchemy."""

    def __init__(self, connection: AsyncConnection, *, token_secret: str) -> None:
        self.connection = connection
        super().__init__(token_secret=token_secret)

    async def insert[int](
        self, authentication_session: AuthenticationSession[int]
    ) -> int:
        """Insert an authentication session into the database."""
        result = await self.connection.execute(
            insert(authentication_session_table)
            .values(**dataclasses.asdict(authentication_session))
            .returning(authentication_session_table.c.id)
        )
        return result.scalar_one()

    async def get_by_token_hash(
        self, token_hash: str
    ) -> AuthenticationSession[object] | None:
        """Retrieve an authentication session by its token hash."""
        result = await self.connection.execute(
            select(authentication_session_table).where(
                authentication_session_table.c.token_hash == token_hash
            )
        )
        row = result.fetchone()
        if row is None:
            return None
        return AuthenticationSession(**row._asdict())

    async def update[int](
        self, authentication_session: AuthenticationSession[int]
    ) -> None:
        """Update an existing authentication session in the database."""
        await self.connection.execute(
            update(authentication_session_table)
            .where(authentication_session_table.c.id == authentication_session.id)
            .values(**dataclasses.asdict(authentication_session))
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
def authentication_session_service(
    sqlalchemy_connection: AsyncConnection,
) -> SQLAlchemyAuthenticationSession:
    """Fixture that provides an instance of SQLAlchemyAuthenticationSession."""
    return SQLAlchemyAuthenticationSession(
        connection=sqlalchemy_connection, token_secret="test_secret"
    )


@pytest.mark.anyio
class TestAuthenticationSessionCreate:
    async def test_returns_valid_session(
        self, authentication_session_service: SQLAlchemyAuthenticationSession
    ) -> None:
        token, session = await authentication_session_service.create()
        assert isinstance(session, AuthenticationSession)
        assert session.id is not None
        assert session.expires_at > int(datetime.datetime.now(datetime.UTC).timestamp())
        assert session.identity_id is None

        token_hash = get_token_hash(
            token, secret=authentication_session_service.token_secret
        )
        assert session.token_hash == token_hash


@pytest.mark.anyio
class TestAuthenticationSessionGetByToken:
    async def test_not_existing_session(
        self, authentication_session_service: SQLAlchemyAuthenticationSession
    ) -> None:
        with pytest.raises(InvalidSessionTokenException):
            await authentication_session_service.get_by_token("token")

    async def test_expired_session(
        self, authentication_session_service: SQLAlchemyAuthenticationSession
    ) -> None:
        token, token_hash = generate_token_hash_pair(
            secret=authentication_session_service.token_secret,
            prefix=authentication_session_service.token_prefix,
        )
        await authentication_session_service.insert(
            AuthenticationSession(
                id=None,
                token_hash=token_hash,
                expires_at=0,
                identity_id=None,
            )
        )

        with pytest.raises(ExpiredSessionException):
            await authentication_session_service.get_by_token(token)

    async def test_valid_session(
        self, authentication_session_service: SQLAlchemyAuthenticationSession
    ) -> None:
        token, token_hash = generate_token_hash_pair(
            secret=authentication_session_service.token_secret,
            prefix=authentication_session_service.token_prefix,
        )
        now = datetime.datetime.now(datetime.UTC).timestamp()
        session_id = await authentication_session_service.insert(
            AuthenticationSession(
                id=None,
                token_hash=token_hash,
                expires_at=int(now + 3600),
                identity_id=None,
            )
        )

        session = await authentication_session_service.get_by_token(token)
        assert session.id == session_id
