import dataclasses
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
from reauth.authentication_session import (
    AuthenticationSession,
    AuthenticationSessionService,
    ExpiredSessionException,
    InvalidSessionTokenException,
    UnavailableFactorException,
)
from reauth.crypto import generate_token_hash_pair, get_token_hash
from reauth.factors import FactorBase
from reauth.timestamp import get_current_timestamp

sqlalchemy_meta = MetaData()
authentication_session_table = Table(
    "authentication_sessions",
    sqlalchemy_meta,
    Column("id", Integer, primary_key=True),
    Column("token_hash", String(64), nullable=False),
    Column("expires_at", Integer, nullable=False),
    Column("identity_id", Integer, nullable=True),
    Column("amr", JSON, nullable=False),
    sqlite_autoincrement=True,
)


@dataclasses.dataclass
class DummyPasswordFactorEnrollment:
    id: int | None
    identity_id: int


class DummyPasswordFactor(FactorBase[DummyPasswordFactorEnrollment]):
    """Dummy factor for testing purposes that simulates a password-based authentication method."""

    AMR = AuthenticationMethodReference.PWD

    def __init__(self) -> None:
        super().__init__(min_prior_factors=0)

    async def get_enrollment(
        self, identity_id: int
    ) -> DummyPasswordFactorEnrollment | None:
        if identity_id != 1:
            return None
        return DummyPasswordFactorEnrollment(id=1, identity_id=identity_id)


@dataclasses.dataclass
class DummyMFAFactorEnrollment:
    id: int | None
    identity_id: int


class DummyMFAFactor(FactorBase[DummyMFAFactorEnrollment]):
    """Dummy factor for testing purposes that simulates a multi-factor authentication method."""

    AMR = AuthenticationMethodReference.MFA

    def __init__(self) -> None:
        super().__init__(min_prior_factors=1)

    async def get_enrollment(self, identity_id: int) -> DummyMFAFactorEnrollment | None:
        if identity_id != 1:
            return None
        return DummyMFAFactorEnrollment(id=1, identity_id=identity_id)


class SQLAlchemyAuthenticationSession(AuthenticationSessionService):
    """Concrete implementation of AuthenticationSessionService using SQLAlchemy."""

    def __init__(
        self,
        connection: AsyncConnection,
        *,
        hash_secret: str,
        factors: set[FactorBase[typing.Any]],
    ) -> None:
        self.connection = connection
        super().__init__(hash_secret=hash_secret, factors=factors)

    async def insert(self, authentication_session: AuthenticationSession) -> int:
        """Insert an authentication session into the database."""
        result = await self.connection.execute(
            insert(authentication_session_table)
            .values(**dataclasses.asdict(authentication_session))
            .returning(authentication_session_table.c.id)
        )
        return result.scalar_one()

    async def get_by_token_hash(self, token_hash: str) -> AuthenticationSession | None:
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

    async def update(self, authentication_session: AuthenticationSession) -> None:
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
def password_factor() -> DummyPasswordFactor:
    """Fixture that provides an instance of DummyPasswordFactor."""
    return DummyPasswordFactor()


@pytest.fixture
def mfa_factor() -> DummyMFAFactor:
    """Fixture that provides an instance of DummyMFAFactor."""
    return DummyMFAFactor()


@pytest.fixture
def authentication_session_service(
    sqlalchemy_connection: AsyncConnection,
    password_factor: DummyPasswordFactor,
    mfa_factor: DummyMFAFactor,
) -> SQLAlchemyAuthenticationSession:
    """Fixture that provides an instance of SQLAlchemyAuthenticationSession."""
    return SQLAlchemyAuthenticationSession(
        connection=sqlalchemy_connection,
        hash_secret="test_secret",
        factors={password_factor, mfa_factor},
    )


@pytest.mark.anyio
class TestAuthenticationSessionCreate:
    async def test_returns_valid_session(
        self, authentication_session_service: SQLAlchemyAuthenticationSession
    ) -> None:
        token, session = await authentication_session_service.create()
        assert isinstance(session, AuthenticationSession)
        assert session.id is not None
        assert session.expires_at > get_current_timestamp()
        assert session.identity_id is None

        token_hash = get_token_hash(
            token, secret=authentication_session_service.hash_secret
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
            secret=authentication_session_service.hash_secret,
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
            secret=authentication_session_service.hash_secret,
            prefix=authentication_session_service.token_prefix,
        )
        session_id = await authentication_session_service.insert(
            AuthenticationSession(
                id=None,
                token_hash=token_hash,
                expires_at=get_current_timestamp() + 3600,
                identity_id=None,
            )
        )

        session = await authentication_session_service.get_by_token(token)
        assert session.id == session_id


@pytest.mark.anyio
class TestGetAvailableFactors:
    async def test_no_identity_zero_factor(
        self, authentication_session_service: SQLAlchemyAuthenticationSession
    ) -> None:
        token, token_hash = generate_token_hash_pair(
            secret=authentication_session_service.hash_secret,
            prefix=authentication_session_service.token_prefix,
        )
        session = AuthenticationSession(
            id=None,
            token_hash=token_hash,
            expires_at=get_current_timestamp() + 3600,
            identity_id=None,
            amr=[],
        )
        session.id = await authentication_session_service.insert(session)

        factors = await authentication_session_service.get_available_factors(session)

        assert len(factors) == 1
        assert isinstance(next(iter(factors)), DummyPasswordFactor)

    async def test_identity_one_factor_enrolled(
        self, authentication_session_service: SQLAlchemyAuthenticationSession
    ) -> None:
        token, token_hash = generate_token_hash_pair(
            secret=authentication_session_service.hash_secret,
            prefix=authentication_session_service.token_prefix,
        )
        session = AuthenticationSession(
            id=None,
            token_hash=token_hash,
            expires_at=get_current_timestamp() + 3600,
            identity_id=1,
            amr=[AuthenticationMethodReference.PWD],
        )
        session.id = await authentication_session_service.insert(session)

        factors = await authentication_session_service.get_available_factors(session)

        assert len(factors) == 1
        assert isinstance(next(iter(factors)), DummyMFAFactor)

    async def test_identity_one_factor_not_enrolled(
        self, authentication_session_service: SQLAlchemyAuthenticationSession
    ) -> None:
        token, token_hash = generate_token_hash_pair(
            secret=authentication_session_service.hash_secret,
            prefix=authentication_session_service.token_prefix,
        )
        session = AuthenticationSession(
            id=None,
            token_hash=token_hash,
            expires_at=get_current_timestamp() + 3600,
            identity_id=2,
            amr=[AuthenticationMethodReference.PWD],
        )
        session.id = await authentication_session_service.insert(session)

        factors = await authentication_session_service.get_available_factors(session)

        assert len(factors) == 0


@pytest.mark.anyio
class TestAdvance:
    async def test_no_identity_zero_factor(
        self,
        authentication_session_service: SQLAlchemyAuthenticationSession,
        password_factor: DummyPasswordFactor,
    ) -> None:
        token, token_hash = generate_token_hash_pair(
            secret=authentication_session_service.hash_secret,
            prefix=authentication_session_service.token_prefix,
        )
        session = AuthenticationSession(
            id=None,
            token_hash=token_hash,
            expires_at=get_current_timestamp() + 3600,
            identity_id=None,
            amr=[],
        )
        session.id = await authentication_session_service.insert(session)

        updated_session = await authentication_session_service.advance(
            session, 1, password_factor
        )

        assert updated_session.id == session.id
        assert updated_session.amr == [AuthenticationMethodReference.PWD]

    async def test_identity_one_factor_enrolled(
        self,
        authentication_session_service: SQLAlchemyAuthenticationSession,
        mfa_factor: DummyMFAFactor,
    ) -> None:
        token, token_hash = generate_token_hash_pair(
            secret=authentication_session_service.hash_secret,
            prefix=authentication_session_service.token_prefix,
        )
        session = AuthenticationSession(
            id=None,
            token_hash=token_hash,
            expires_at=get_current_timestamp() + 3600,
            identity_id=1,
            amr=[AuthenticationMethodReference.PWD],
        )
        session.id = await authentication_session_service.insert(session)

        updated_session = await authentication_session_service.advance(
            session, 1, mfa_factor
        )

        assert updated_session.id == session.id
        assert updated_session.amr == [
            AuthenticationMethodReference.PWD,
            AuthenticationMethodReference.MFA,
        ]

    async def test_identity_one_factor_not_enrolled(
        self,
        authentication_session_service: SQLAlchemyAuthenticationSession,
        mfa_factor: DummyMFAFactor,
    ) -> None:
        token, token_hash = generate_token_hash_pair(
            secret=authentication_session_service.hash_secret,
            prefix=authentication_session_service.token_prefix,
        )
        session = AuthenticationSession(
            id=None,
            token_hash=token_hash,
            expires_at=get_current_timestamp() + 3600,
            identity_id=2,
            amr=[AuthenticationMethodReference.PWD],
        )
        session.id = await authentication_session_service.insert(session)

        with pytest.raises(UnavailableFactorException):
            await authentication_session_service.advance(session, 1, mfa_factor)
