import base64
import dataclasses
import secrets
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
)
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine
from sqlalchemy.sql.expression import update

from reauth.factors.hotp import HOTPEnrollment, HOTPFactor, InvalidHOTPCodeException

sqlalchemy_meta = MetaData()
hotp_table = Table(
    "hotps",
    sqlalchemy_meta,
    Column("id", Integer, primary_key=True),
    Column("secret", String(32), nullable=False),
    Column("algorithm", String(4), nullable=False),
    Column("code_length", Integer, nullable=False),
    Column("counter", Integer, nullable=False),
    Column("identity_id", Integer, nullable=False),
    sqlite_autoincrement=True,
)


class SQLAlchemyHOTPFactor(HOTPFactor):
    """Concrete implementation of HOTPFactor using SQLAlchemy."""

    def __init__(self, connection: AsyncConnection) -> None:
        self.connection = connection
        super().__init__()

    async def get_enrollment(self, identity_id: int) -> HOTPEnrollment | None:
        """Retrieve the HOTP enrollment for a given identity."""
        result = await self.connection.execute(
            select(hotp_table).where(hotp_table.c.identity_id == identity_id)
        )
        row = result.fetchone()
        if row is None:
            return None
        return HOTPEnrollment(**row._asdict())

    async def insert(self, hotp: HOTPEnrollment) -> int:
        """Insert an HOTP into the database."""
        result = await self.connection.execute(
            insert(hotp_table)
            .values(**dataclasses.asdict(hotp))
            .returning(hotp_table.c.id)
        )
        return result.scalar_one()

    async def update(self, hotp: HOTPEnrollment) -> None:
        """Update an existing HOTP in the database."""
        await self.connection.execute(
            update(hotp_table)
            .where(hotp_table.c.id == hotp.id)
            .values(**dataclasses.asdict(hotp))
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
def hotp_factor(
    sqlalchemy_connection: AsyncConnection,
) -> SQLAlchemyHOTPFactor:
    """Fixture that provides an instance of SQLAlchemyHOTPFactor."""
    return SQLAlchemyHOTPFactor(connection=sqlalchemy_connection)


class TestHOTP:
    def test_get_provisioning_uri(self) -> None:
        secret = secrets.token_bytes(20)  # 160-bit secret key
        base64.b32encode(secret).decode("ascii")
        hotp = HOTPEnrollment(
            id=1,
            secret=base64.b32encode(secret).decode("ascii"),
            algorithm="sha1",
            code_length=6,
            counter=0,
            identity_id=123,
        )
        uri = hotp.get_provisioning_uri("reauth@example.com", "Reauth Tests")
        assert uri.startswith("otpauth://hotp/")


@pytest.mark.anyio
class TestHOTPEnroll:
    async def test_returns_valid_hotp(self, hotp_factor: SQLAlchemyHOTPFactor) -> None:
        identity_id = 123
        hotp = await hotp_factor.enroll(identity_id)

        assert isinstance(hotp, HOTPEnrollment)
        assert hotp.id is not None
        assert hotp.identity_id == identity_id
        assert hotp.counter == 0
        assert hotp.code_length == 6
        assert hotp.algorithm == "sha1"
        assert len(hotp.secret) == 32  # Base32-encoded 160-bit key is 32 chars


@pytest.mark.anyio
class TestHOTPVerify:
    async def test_invalid_code(self, hotp_factor: SQLAlchemyHOTPFactor) -> None:
        identity_id = 123
        hotp = await hotp_factor.enroll(identity_id)

        with pytest.raises(InvalidHOTPCodeException):
            await hotp_factor.verify(hotp, "000000")

        assert hotp.counter == 0

    async def test_valid_code(self, hotp_factor: SQLAlchemyHOTPFactor) -> None:
        identity_id = 123
        hotp = await hotp_factor.enroll(identity_id)

        expected_code = hotp._impl.generate(hotp.counter).decode("ascii")

        await hotp_factor.verify(hotp, expected_code)

        assert hotp.counter == 1

    async def test_beyond_lookahead(self, hotp_factor: SQLAlchemyHOTPFactor) -> None:
        hotp = await hotp_factor.enroll(123)

        expected_code = hotp._impl.generate(hotp.counter + 10).decode("ascii")

        with pytest.raises(InvalidHOTPCodeException):
            await hotp_factor.verify(hotp, expected_code)

        assert hotp.counter == 0

    async def test_valid_code_desync(self, hotp_factor: SQLAlchemyHOTPFactor) -> None:
        hotp = await hotp_factor.enroll(123)

        expected_code = hotp._impl.generate(hotp.counter + 4).decode("ascii")

        await hotp_factor.verify(hotp, expected_code)

        assert hotp.counter == 5
