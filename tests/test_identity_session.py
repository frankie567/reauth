import dataclasses
import datetime
import typing
from collections.abc import AsyncGenerator

import pytest
from sqlalchemy import (
    JSON,
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

from reauth.amr import AuthenticationMethodReference
from reauth.crypto import TokenHash, generate_token_hash_pair, get_token_hash
from reauth.identity_session import (
    ExpiredSessionException,
    IdentitySession,
    IdentitySessionService,
    InvalidSessionTokenException,
)
from reauth.timestamp import get_current_timestamp

sqlalchemy_meta = MetaData()
identity_session_table = Table(
    "identity_sessions",
    sqlalchemy_meta,
    Column("id", Integer, primary_key=True),
    Column("token_hash", String(64), nullable=False, unique=True),
    Column("expires_at", Integer, nullable=False),
    Column("identity_id", Integer, nullable=False),
    Column("amr", JSON, nullable=False),
    Column("context", JSON, nullable=True),
    sqlite_autoincrement=True,
)


class SQLAlchemyIdentitySessionService(IdentitySessionService):
    def __init__(self, connection: AsyncConnection, **kwargs: typing.Any) -> None:
        self.connection = connection
        super().__init__(**kwargs)

    async def insert(self, identity_session: IdentitySession) -> int:
        result = await self.connection.execute(
            insert(identity_session_table)
            .values(**dataclasses.asdict(identity_session))
            .returning(identity_session_table.c.id)
        )
        return result.scalar_one()

    async def get_by_token_hash(self, token_hash: TokenHash) -> IdentitySession | None:
        result = await self.connection.execute(
            select(identity_session_table).where(
                identity_session_table.c.token_hash == token_hash
            )
        )
        row = result.fetchone()
        return IdentitySession(**row._asdict()) if row is not None else None

    async def delete(self, identity_session: IdentitySession) -> None:
        await self.connection.execute(
            delete(identity_session_table).where(
                identity_session_table.c.id == identity_session.id
            )
        )


@pytest.fixture
async def sqlalchemy_connection(
    sqlalchemy_engine: AsyncEngine,
) -> AsyncGenerator[AsyncConnection]:
    async with sqlalchemy_engine.begin() as connection:
        await connection.run_sync(sqlalchemy_meta.create_all)
        yield connection
        await connection.run_sync(sqlalchemy_meta.drop_all)


@pytest.fixture
def identity_session_service(
    sqlalchemy_connection: AsyncConnection,
) -> SQLAlchemyIdentitySessionService:
    return SQLAlchemyIdentitySessionService(
        connection=sqlalchemy_connection, hash_secret="test_secret"
    )


@pytest.mark.anyio
class TestIdentitySessionIssue:
    async def test_returns_persisted_session(
        self,
        identity_session_service: SQLAlchemyIdentitySessionService,
    ) -> None:
        started_at = get_current_timestamp()

        token, session = await identity_session_service.issue(
            1, amr=[AuthenticationMethodReference.PWD]
        )

        assert token.startswith("reauth_is_")
        assert session.id is not None
        assert session.identity_id == 1
        assert session.amr == [AuthenticationMethodReference.PWD]
        assert session.context is None
        assert (
            started_at + 86400 <= session.expires_at <= get_current_timestamp() + 86400
        )
        assert session.token_hash == get_token_hash(
            token, secret=identity_session_service.hash_secret
        )
        stored = await identity_session_service.get_by_token_hash(session.token_hash)
        assert stored == session

    async def test_with_context(
        self, identity_session_service: SQLAlchemyIdentitySessionService
    ) -> None:
        _, session = await identity_session_service.issue(
            1, amr=[AuthenticationMethodReference.PWD], device="laptop"
        )

        stored = await identity_session_service.get_by_token_hash(session.token_hash)
        assert stored is not None
        assert stored.context == {"device": "laptop"}

    async def test_custom_prefix_and_lifetime(
        self,
        sqlalchemy_connection: AsyncConnection,
    ) -> None:
        service = SQLAlchemyIdentitySessionService(
            connection=sqlalchemy_connection,
            hash_secret="test_secret",
            token_prefix="custom_",
            lifetime=datetime.timedelta(hours=1),
        )

        started_at = get_current_timestamp()
        token, session = await service.issue(1, amr=[AuthenticationMethodReference.PWD])

        assert token.startswith("custom_")
        assert started_at + 3600 <= session.expires_at <= get_current_timestamp() + 3600


@pytest.mark.anyio
class TestIdentitySessionValidate:
    async def test_not_existing_session(
        self, identity_session_service: SQLAlchemyIdentitySessionService
    ) -> None:
        with pytest.raises(InvalidSessionTokenException):
            await identity_session_service.validate("unknown_token")

    async def test_non_ascii_token(
        self, identity_session_service: SQLAlchemyIdentitySessionService
    ) -> None:
        with pytest.raises(InvalidSessionTokenException):
            await identity_session_service.validate("invalid_é")

    async def test_expired_session(
        self,
        identity_session_service: SQLAlchemyIdentitySessionService,
    ) -> None:
        token, token_hash = generate_token_hash_pair(
            secret=identity_session_service.hash_secret,
            prefix=identity_session_service.token_prefix,
        )
        await identity_session_service.insert(
            IdentitySession(
                id=None,
                token_hash=token_hash,
                expires_at=0,
                identity_id=1,
                amr=[AuthenticationMethodReference.PWD],
            )
        )

        with pytest.raises(ExpiredSessionException):
            await identity_session_service.validate(token)

    async def test_valid_session(
        self,
        identity_session_service: SQLAlchemyIdentitySessionService,
    ) -> None:
        token, token_hash = generate_token_hash_pair(
            secret=identity_session_service.hash_secret,
            prefix=identity_session_service.token_prefix,
        )
        session = IdentitySession(
            id=None,
            token_hash=token_hash,
            expires_at=get_current_timestamp() + 3600,
            identity_id=1,
            amr=[AuthenticationMethodReference.PWD],
            context={"device": "laptop"},
        )
        session.id = await identity_session_service.insert(session)

        validated = await identity_session_service.validate(token)

        assert validated == session


@pytest.mark.anyio
class TestIdentitySessionRevoke:
    async def test_deletes_session(
        self, identity_session_service: SQLAlchemyIdentitySessionService
    ) -> None:
        _, token_hash = generate_token_hash_pair(
            secret=identity_session_service.hash_secret,
            prefix=identity_session_service.token_prefix,
        )
        session = IdentitySession(
            id=None,
            token_hash=token_hash,
            expires_at=1000,
            identity_id=1,
            amr=[AuthenticationMethodReference.PWD],
        )
        session.id = await identity_session_service.insert(session)

        await identity_session_service.revoke(session)

        assert await identity_session_service.get_by_token_hash(token_hash) is None

    async def test_already_deleted_session(
        self, identity_session_service: SQLAlchemyIdentitySessionService
    ) -> None:
        _, token_hash = generate_token_hash_pair(
            secret=identity_session_service.hash_secret,
            prefix=identity_session_service.token_prefix,
        )
        session = IdentitySession(
            id=None,
            token_hash=token_hash,
            expires_at=1000,
            identity_id=1,
            amr=[AuthenticationMethodReference.PWD],
        )
        session.id = await identity_session_service.insert(session)
        await identity_session_service.delete(session)

        await identity_session_service.revoke(session)

        assert await identity_session_service.get_by_token_hash(token_hash) is None
