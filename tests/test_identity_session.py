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
    insert,
    select,
    update,
)
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from reauth.amr import AuthenticationMethodReference
from reauth.crypto import TokenHash, get_token_hash
from reauth.identity_session import (
    ExpiredRefreshTokenException,
    ExpiredSessionException,
    IdentitySession,
    IdentitySessionService,
    InvalidRefreshTokenException,
    InvalidSessionTokenException,
    ReusedRefreshTokenException,
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
    Column("refresh_token_hash", String(64), nullable=True, unique=True),
    Column("refresh_token_expires_at", Integer, nullable=True),
    Column("family_id", Integer, nullable=True, index=True),
    Column("replaced_by_id", Integer, nullable=True),
    Column("revoked_at", Integer, nullable=True),
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
        session_id = result.scalar_one()
        if identity_session.family_id is None:
            await self.connection.execute(
                update(identity_session_table)
                .where(identity_session_table.c.id == session_id)
                .values(family_id=session_id)
            )
        return session_id

    async def get_by_token_hash(self, token_hash: TokenHash) -> IdentitySession | None:
        result = await self.connection.execute(
            select(identity_session_table).where(
                identity_session_table.c.token_hash == token_hash
            )
        )
        row = result.mappings().one_or_none()
        return IdentitySession(**row) if row is not None else None

    async def get_by_refresh_token_hash(
        self, refresh_token_hash: TokenHash
    ) -> IdentitySession | None:
        result = await self.connection.execute(
            select(identity_session_table).where(
                identity_session_table.c.refresh_token_hash == refresh_token_hash
            )
        )
        row = result.mappings().one_or_none()
        return IdentitySession(**row) if row is not None else None

    async def replace(
        self, previous_session: IdentitySession, new_session: IdentitySession
    ) -> int:
        session_id = await self.insert(new_session)
        await self.connection.execute(
            update(identity_session_table)
            .where(identity_session_table.c.id == previous_session.id)
            .values(replaced_by_id=session_id)
        )
        return session_id

    async def revoke_family(self, identity_session: IdentitySession) -> None:
        await self.connection.execute(
            update(identity_session_table)
            .where(
                identity_session_table.c.family_id == identity_session.family_id,
                identity_session_table.c.revoked_at.is_(None),
            )
            .values(revoked_at=identity_session.revoked_at)
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


@pytest.fixture
def session() -> IdentitySession:
    return IdentitySession(
        id=None,
        token_hash=get_token_hash("access_token", secret="test_secret"),
        expires_at=get_current_timestamp() + 3600,
        identity_id=1,
        amr=[AuthenticationMethodReference.PWD],
        context={"device": "laptop"},
        refresh_token_hash=get_token_hash("refresh_token", secret="test_secret"),
        refresh_token_expires_at=get_current_timestamp() + 7200,
    )


@pytest.fixture
async def session_family(
    identity_session_service: SQLAlchemyIdentitySessionService,
    session: IdentitySession,
) -> list[IdentitySession]:
    family = [
        dataclasses.replace(
            session,
            id=session_id,
            family_id=1,
            token_hash=get_token_hash(f"access_{session_id}", secret="test_secret"),
            refresh_token_hash=get_token_hash(
                f"refresh_{session_id}", secret="test_secret"
            ),
            replaced_by_id=session_id + 1 if session_id < 3 else None,
        )
        for session_id in range(1, 4)
    ]
    for member in family:
        await identity_session_service.insert(member)
    return family


@pytest.mark.anyio
class TestIdentitySessionIssue:
    async def test_returns_persisted_session(
        self, identity_session_service: SQLAlchemyIdentitySessionService
    ) -> None:
        started_at = get_current_timestamp()

        token, refresh_token, session = await identity_session_service.issue(
            1, amr=[AuthenticationMethodReference.PWD]
        )

        assert token.startswith("reauth_is_")
        assert session.id is not None
        assert session.family_id == session.id
        assert session.identity_id == 1
        assert session.amr == [AuthenticationMethodReference.PWD]
        assert session.context is None
        assert refresh_token is None
        assert session.refresh_token_hash is None
        assert session.refresh_token_expires_at is None
        assert (
            started_at + 86400 <= session.expires_at <= get_current_timestamp() + 86400
        )
        assert session.token_hash == get_token_hash(token, secret="test_secret")
        assert (
            await identity_session_service.get_by_token_hash(session.token_hash)
            == session
        )

    async def test_with_context(
        self, identity_session_service: SQLAlchemyIdentitySessionService
    ) -> None:
        _, _, session = await identity_session_service.issue(
            1, amr=[AuthenticationMethodReference.PWD], device="laptop"
        )

        stored = await identity_session_service.get_by_token_hash(session.token_hash)
        assert stored is not None
        assert stored.context == {"device": "laptop"}

    async def test_with_refresh_token(
        self, identity_session_service: SQLAlchemyIdentitySessionService
    ) -> None:
        started_at = get_current_timestamp()

        token, refresh_token, session = await identity_session_service.issue(
            1, amr=[AuthenticationMethodReference.PWD], refresh_token=True
        )

        assert refresh_token is not None
        assert refresh_token.startswith("reauth_isr_")
        assert refresh_token != token
        assert session.refresh_token_hash is not None
        assert session.refresh_token_hash == get_token_hash(
            refresh_token, secret="test_secret"
        )
        assert session.refresh_token_expires_at is not None
        assert (
            started_at + 2592000
            <= session.refresh_token_expires_at
            <= get_current_timestamp() + 2592000
        )
        assert session.expires_at < session.refresh_token_expires_at
        assert (
            await identity_session_service.get_by_refresh_token_hash(
                session.refresh_token_hash
            )
            == session
        )

    async def test_custom_prefixes_and_lifetimes(
        self, sqlalchemy_connection: AsyncConnection
    ) -> None:
        service = SQLAlchemyIdentitySessionService(
            connection=sqlalchemy_connection,
            hash_secret="test_secret",
            token_prefix="custom_",
            lifetime=datetime.timedelta(hours=1),
            refresh_token_prefix="custom_refresh_",
            refresh_token_lifetime=datetime.timedelta(days=1),
        )
        started_at = get_current_timestamp()

        token, refresh_token, session = await service.issue(
            1, amr=[AuthenticationMethodReference.PWD], refresh_token=True
        )

        assert token.startswith("custom_")
        assert refresh_token is not None and refresh_token.startswith("custom_refresh_")
        assert started_at + 3600 <= session.expires_at <= get_current_timestamp() + 3600
        assert session.refresh_token_expires_at is not None
        assert (
            started_at + 86400
            <= session.refresh_token_expires_at
            <= get_current_timestamp() + 86400
        )

    async def test_caps_access_at_refresh_deadline(
        self, sqlalchemy_connection: AsyncConnection
    ) -> None:
        service = SQLAlchemyIdentitySessionService(
            connection=sqlalchemy_connection,
            hash_secret="test_secret",
            refresh_token_lifetime=datetime.timedelta(hours=1),
        )

        _, _, session = await service.issue(1, amr=[], refresh_token=True)

        assert session.expires_at == session.refresh_token_expires_at


@pytest.mark.anyio
class TestIdentitySessionValidate:
    @pytest.mark.parametrize("token", ["unknown_token", "invalid_é", "refresh_token"])
    async def test_invalid_token(
        self,
        identity_session_service: SQLAlchemyIdentitySessionService,
        session: IdentitySession,
        token: str,
    ) -> None:
        await identity_session_service.insert(session)

        with pytest.raises(InvalidSessionTokenException):
            await identity_session_service.validate(token)

    @pytest.mark.parametrize("state", [{"revoked_at": 0}, {"replaced_by_id": 2}])
    async def test_inactive_session(
        self,
        identity_session_service: SQLAlchemyIdentitySessionService,
        session: IdentitySession,
        state: dict[str, int],
    ) -> None:
        await identity_session_service.insert(dataclasses.replace(session, **state))

        with pytest.raises(InvalidSessionTokenException):
            await identity_session_service.validate("access_token")

    async def test_expired_session(
        self,
        identity_session_service: SQLAlchemyIdentitySessionService,
        session: IdentitySession,
    ) -> None:
        session.expires_at = 0
        await identity_session_service.insert(session)

        with pytest.raises(ExpiredSessionException):
            await identity_session_service.validate("access_token")

    async def test_valid_session(
        self,
        identity_session_service: SQLAlchemyIdentitySessionService,
        session: IdentitySession,
    ) -> None:
        session.id = await identity_session_service.insert(session)
        session.family_id = session.id

        validated = await identity_session_service.validate("access_token")

        assert validated == session


@pytest.mark.anyio
class TestIdentitySessionRefresh:
    async def test_replaces_expired_access_session(
        self,
        identity_session_service: SQLAlchemyIdentitySessionService,
        session: IdentitySession,
    ) -> None:
        session.expires_at = 0
        session.id = await identity_session_service.insert(session)

        token, refresh_token, refreshed = await identity_session_service.refresh(
            "refresh_token"
        )

        assert refreshed.id != session.id
        assert refreshed.family_id == session.id
        assert refreshed.identity_id == session.identity_id
        assert refreshed.amr == session.amr
        assert refreshed.context == session.context
        assert refreshed.refresh_token_expires_at == session.refresh_token_expires_at
        assert refreshed.expires_at == session.refresh_token_expires_at
        assert refreshed.token_hash == get_token_hash(token, secret="test_secret")
        assert refreshed.token_hash != session.token_hash
        assert refresh_token is not None and refresh_token.startswith("reauth_isr_")
        assert refreshed.refresh_token_hash == get_token_hash(
            refresh_token, secret="test_secret"
        )
        assert refreshed.refresh_token_hash != session.refresh_token_hash
        assert (
            await identity_session_service.get_by_token_hash(refreshed.token_hash)
            == refreshed
        )
        previous = await identity_session_service.get_by_token_hash(session.token_hash)
        assert previous is not None
        assert previous.replaced_by_id == refreshed.id
        assert previous.refresh_token_hash == session.refresh_token_hash

    async def test_preserves_deadline_across_generations(
        self,
        identity_session_service: SQLAlchemyIdentitySessionService,
        session_family: list[IdentitySession],
    ) -> None:
        identity_session_service.lifetime = datetime.timedelta(minutes=15)
        started_at = get_current_timestamp()

        _, _, refreshed = await identity_session_service.refresh("refresh_3")

        assert refreshed.family_id == session_family[0].id
        assert (
            refreshed.refresh_token_expires_at
            == session_family[0].refresh_token_expires_at
        )
        assert started_at + 900 <= refreshed.expires_at <= get_current_timestamp() + 900

    async def test_without_new_refresh_token(
        self,
        identity_session_service: SQLAlchemyIdentitySessionService,
        session: IdentitySession,
    ) -> None:
        session.id = await identity_session_service.insert(session)

        _, refresh_token, refreshed = await identity_session_service.refresh(
            "refresh_token", refresh_token=False
        )

        assert refresh_token is None
        assert refreshed.refresh_token_hash is None
        assert refreshed.refresh_token_expires_at is None
        assert refreshed.expires_at == session.refresh_token_expires_at
        assert refreshed.family_id == session.id
        assert (
            await identity_session_service.get_by_token_hash(refreshed.token_hash)
            == refreshed
        )
        previous = await identity_session_service.get_by_token_hash(session.token_hash)
        assert previous is not None and previous.replaced_by_id == refreshed.id

    @pytest.mark.parametrize("token", ["unknown_token", "invalid_é", "access_token"])
    async def test_invalid_token(
        self,
        identity_session_service: SQLAlchemyIdentitySessionService,
        session: IdentitySession,
        token: str,
    ) -> None:
        await identity_session_service.insert(session)

        with pytest.raises(InvalidRefreshTokenException):
            await identity_session_service.refresh(token)

    async def test_revoked_session(
        self,
        identity_session_service: SQLAlchemyIdentitySessionService,
        session: IdentitySession,
    ) -> None:
        session.revoked_at = 0
        await identity_session_service.insert(session)

        with pytest.raises(InvalidRefreshTokenException):
            await identity_session_service.refresh("refresh_token")

    async def test_expired_refresh_token(
        self,
        identity_session_service: SQLAlchemyIdentitySessionService,
        session: IdentitySession,
    ) -> None:
        session.refresh_token_expires_at = 0
        await identity_session_service.insert(session)

        with pytest.raises(ExpiredRefreshTokenException):
            await identity_session_service.refresh("refresh_token")

    @pytest.mark.parametrize("final_refresh_token", [True, False])
    async def test_reuse_revokes_entire_family(
        self,
        identity_session_service: SQLAlchemyIdentitySessionService,
        session_family: list[IdentitySession],
        sqlalchemy_connection: AsyncConnection,
        final_refresh_token: bool,
    ) -> None:
        if not final_refresh_token:
            await sqlalchemy_connection.execute(
                update(identity_session_table)
                .where(identity_session_table.c.id == 3)
                .values(refresh_token_hash=None, refresh_token_expires_at=None)
            )

        with pytest.raises(ReusedRefreshTokenException):
            await identity_session_service.refresh("refresh_1")

        for member in session_family:
            stored = await identity_session_service.get_by_token_hash(member.token_hash)
            assert stored is not None and stored.revoked_at is not None


@pytest.mark.anyio
class TestIdentitySessionRevoke:
    @pytest.mark.parametrize(
        "token", ["access_1", "refresh_1", "access_3", "refresh_3"]
    )
    async def test_revokes_family_using_either_token(
        self,
        identity_session_service: SQLAlchemyIdentitySessionService,
        session_family: list[IdentitySession],
        token: str,
    ) -> None:
        await identity_session_service.revoke(token)

        for member in session_family:
            stored = await identity_session_service.get_by_token_hash(member.token_hash)
            assert stored is not None and stored.revoked_at is not None
            assert stored.refresh_token_hash == member.refresh_token_hash
            assert stored.replaced_by_id == member.replaced_by_id

    async def test_expired_token_and_independent_family(
        self,
        identity_session_service: SQLAlchemyIdentitySessionService,
        session_family: list[IdentitySession],
        session: IdentitySession,
    ) -> None:
        session.expires_at = 0
        session.refresh_token_hash = None
        session.refresh_token_expires_at = None
        await identity_session_service.insert(session)

        await identity_session_service.revoke("access_token")

        stored = await identity_session_service.get_by_token_hash(session.token_hash)
        assert stored is not None and stored.revoked_at is not None
        for member in session_family:
            stored = await identity_session_service.get_by_token_hash(member.token_hash)
            assert stored is not None and stored.revoked_at is None

    @pytest.mark.parametrize("token", ["unknown_token", "invalid_é"])
    async def test_unknown_token(
        self,
        identity_session_service: SQLAlchemyIdentitySessionService,
        token: str,
    ) -> None:
        await identity_session_service.revoke(token)

    async def test_already_revoked_family(
        self,
        identity_session_service: SQLAlchemyIdentitySessionService,
        session: IdentitySession,
    ) -> None:
        session.revoked_at = 123
        await identity_session_service.insert(session)

        await identity_session_service.revoke("access_token")

        stored = await identity_session_service.get_by_token_hash(session.token_hash)
        assert stored is not None and stored.revoked_at == 123
