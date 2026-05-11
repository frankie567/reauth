import base64
import dataclasses
import secrets
import time
from collections.abc import AsyncGenerator

import pytest
from sqlalchemy import (
    Column,
    Integer,
    MetaData,
    String,
    Table,
    insert,
)
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine
from sqlalchemy.sql.expression import update

from reauth.factors.totp import (
    TOTP,
    InvalidTOTPCodeException,
    TOTPAlgorithm,
    TOTPFactor,
)

sqlalchemy_meta = MetaData()
totp_table = Table(
    "totps",
    sqlalchemy_meta,
    Column("id", Integer, primary_key=True),
    Column("secret", String(32), nullable=False),
    Column("algorithm", String(16), nullable=False),
    Column("code_length", Integer, nullable=False),
    Column("time_step", Integer, nullable=False),
    Column("identity_id", Integer, nullable=False),
    Column("last_verified_time_step", Integer, nullable=True),
    sqlite_autoincrement=True,
)


class SQLAlchemyTOTPFactor(TOTPFactor):
    """Concrete implementation of TOTPFactor using SQLAlchemy."""

    def __init__(
        self, connection: AsyncConnection, *, algorithm: TOTPAlgorithm = "sha256"
    ) -> None:
        self.connection = connection
        super().__init__(algorithm=algorithm)

    async def insert(self, totp: TOTP) -> int:
        """Insert a TOTP into the database."""
        result = await self.connection.execute(
            insert(totp_table)
            .values(**dataclasses.asdict(totp))
            .returning(totp_table.c.id)
        )
        return result.scalar_one()

    async def update(self, totp: TOTP) -> None:
        """Update an existing TOTP in the database."""
        await self.connection.execute(
            update(totp_table)
            .where(totp_table.c.id == totp.id)
            .values(**dataclasses.asdict(totp))
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


@pytest.fixture(params=["sha1", "sha256", "sha512"])
def totp_factor(
    request: pytest.FixtureRequest,
    sqlalchemy_connection: AsyncConnection,
) -> SQLAlchemyTOTPFactor:
    """Fixture that provides an instance of SQLAlchemyTOTPFactor."""
    return SQLAlchemyTOTPFactor(
        connection=sqlalchemy_connection, algorithm=request.param
    )


class TestTOTP:
    def test_get_provisioning_uri(self) -> None:
        secret = secrets.token_bytes(20)
        totp = TOTP(
            id=1,
            secret=base64.b32encode(secret).decode("ascii"),
            algorithm="sha256",
            code_length=6,
            time_step=30,
            identity_id=123,
        )
        uri = totp.get_provisioning_uri("reauth@example.com", "Reauth Tests")
        assert uri.startswith("otpauth://totp/")


@pytest.mark.anyio
class TestTOTPEnroll:
    async def test_returns_valid_totp(self, totp_factor: SQLAlchemyTOTPFactor) -> None:
        identity_id = 123
        totp = await totp_factor.enroll(identity_id)

        assert isinstance(totp, TOTP)
        assert totp.id is not None
        assert totp.identity_id == identity_id
        assert totp.code_length == 6
        assert totp.algorithm == totp_factor.algorithm
        assert totp.time_step == 30
        assert totp.last_verified_time_step is None
        assert len(totp.secret) == 32


@pytest.mark.anyio
class TestTOTPVerify:
    async def test_invalid_code(self, totp_factor: SQLAlchemyTOTPFactor) -> None:
        totp = await totp_factor.enroll(123)

        with pytest.raises(InvalidTOTPCodeException):
            await totp_factor.verify(totp, "000000")

    async def test_valid_code(self, totp_factor: SQLAlchemyTOTPFactor) -> None:
        totp = await totp_factor.enroll(123)

        current_time = time.time()
        expected_code = totp._impl.generate(current_time).decode("ascii")

        await totp_factor.verify(totp, expected_code)

    async def test_beyond_drift_tolerance(
        self, totp_factor: SQLAlchemyTOTPFactor
    ) -> None:
        totp = await totp_factor.enroll(123)

        expected_code = totp._impl.generate(9999999999).decode("ascii")

        with pytest.raises(InvalidTOTPCodeException):
            await totp_factor.verify(totp, expected_code)

    async def test_within_drift_tolerance(
        self, totp_factor: SQLAlchemyTOTPFactor
    ) -> None:
        totp = await totp_factor.enroll(123)

        expected_code = totp._impl.generate(time.time() + 30).decode("ascii")

        await totp_factor.verify(totp, expected_code)

    async def test_replay_protection_same_time_step(
        self, totp_factor: SQLAlchemyTOTPFactor
    ) -> None:
        totp = await totp_factor.enroll(123)

        current_time = int(time.time())
        expected_code = totp._impl.generate(current_time).decode("ascii")

        # First verification should succeed
        await totp_factor.verify(totp, expected_code)
        assert totp.last_verified_time_step is not None

        # Second verification with same code should fail (replay)
        with pytest.raises(InvalidTOTPCodeException):
            await totp_factor.verify(totp, expected_code)

    async def test_replay_protection_previous_time_step(
        self, totp_factor: SQLAlchemyTOTPFactor
    ) -> None:
        totp = await totp_factor.enroll(123)

        current_time = int(time.time())
        # Generate code for time step T-1
        past_time = current_time - totp.time_step
        past_code = totp._impl.generate(past_time).decode("ascii")

        # First verify current code to set last_verified_time_step
        current_code = totp._impl.generate(current_time).decode("ascii")
        await totp_factor.verify(totp, current_code)

        # Now past code should be rejected
        with pytest.raises(InvalidTOTPCodeException):
            await totp_factor.verify(totp, past_code)

    async def test_future_time_step_accepted(
        self, totp_factor: SQLAlchemyTOTPFactor
    ) -> None:
        totp = await totp_factor.enroll(123)

        current_time = int(time.time())

        # Verify code at current time
        current_code = totp._impl.generate(current_time).decode("ascii")
        await totp_factor.verify(totp, current_code)

        # Code from next time step should still work (within drift tolerance)
        next_time = current_time + totp.time_step
        next_code = totp._impl.generate(next_time).decode("ascii")
        await totp_factor.verify(totp, next_code)
