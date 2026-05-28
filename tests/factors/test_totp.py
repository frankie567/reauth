import base64
import dataclasses
import secrets
import time
import typing
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

from reauth.factors.totp import (
    AlreadyEnabledTOTPException,
    AlreadyEnrolledTOTPException,
    InvalidTOTPCodeException,
    NotEnabledTOTPException,
    NotEnrolledTOTPException,
    TOTPAlgorithm,
    TOTPEnrollment,
    TOTPFactor,
)

sqlalchemy_meta = MetaData()
totp_table = Table(
    "totps",
    sqlalchemy_meta,
    Column("id", Integer, primary_key=True),
    Column("identity_id", Integer, nullable=False),
    Column("enabled", Integer, nullable=False, default=0),
    Column("secret", String(32), nullable=False),
    Column("algorithm", String(16), nullable=False),
    Column("code_length", Integer, nullable=False),
    Column("time_step", Integer, nullable=False),
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

    async def get_by_identity_id(self, identity_id: int) -> TOTPEnrollment | None:
        """Retrieve the TOTP enrollment for a given identity, regardless of enabled state."""
        result = await self.connection.execute(
            select(totp_table).where(totp_table.c.identity_id == identity_id)
        )
        row = result.fetchone()
        if row is None:
            return None
        return TOTPEnrollment(**row._asdict())

    async def insert(self, totp: TOTPEnrollment) -> int:
        """Insert a TOTP into the database."""
        result = await self.connection.execute(
            insert(totp_table)
            .values(**dataclasses.asdict(totp))
            .returning(totp_table.c.id)
        )
        return result.scalar_one()

    async def update(self, totp: TOTPEnrollment) -> None:
        """Update an existing TOTP in the database."""
        await self.connection.execute(
            update(totp_table)
            .where(totp_table.c.id == totp.id)
            .values(**dataclasses.asdict(totp))
        )

    async def delete(self, totp: TOTPEnrollment) -> None:
        """Delete a TOTP from the database."""
        await self.connection.execute(
            totp_table.delete().where(totp_table.c.id == totp.id)
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


class MakeTOTPCallable(typing.Protocol):
    async def __call__(
        self,
        identity_id: int = 123,
        enabled: bool = False,
        last_verified_time_step: int | None = None,
    ) -> TOTPEnrollment: ...


@pytest.fixture
def make_totp(
    totp_factor: SQLAlchemyTOTPFactor,
) -> MakeTOTPCallable:
    """Factory fixture to create TOTPEnrollment instances with optional enabled state."""

    async def _make_totp(
        identity_id: int = 123,
        enabled: bool = False,
        last_verified_time_step: int | None = None,
    ) -> TOTPEnrollment:
        secret = secrets.token_bytes(20)
        totp = TOTPEnrollment(
            id=None,
            identity_id=identity_id,
            enabled=enabled,
            secret=base64.b32encode(secret).decode("ascii"),
            algorithm=totp_factor.algorithm,
            code_length=6,
            time_step=30,
            last_verified_time_step=last_verified_time_step,
        )
        totp.id = await totp_factor.insert(totp)
        return totp

    return _make_totp


class TestTOTP:
    def test_get_provisioning_uri(self) -> None:
        secret = secrets.token_bytes(20)
        totp = TOTPEnrollment(
            id=1,
            identity_id=123,
            enabled=True,
            secret=base64.b32encode(secret).decode("ascii"),
            algorithm="sha256",
            code_length=6,
            time_step=30,
        )
        uri = totp.get_provisioning_uri("reauth@example.com", "Reauth Tests")
        assert uri.startswith("otpauth://totp/")


@pytest.mark.anyio
class TestTOTPEnroll:
    async def test_returns_valid_totp(self, totp_factor: SQLAlchemyTOTPFactor) -> None:
        identity_id = 123
        totp = await totp_factor.enroll(identity_id)

        assert isinstance(totp, TOTPEnrollment)
        assert totp.id is not None
        assert totp.identity_id == identity_id
        assert totp.code_length == 6
        assert totp.algorithm == totp_factor.algorithm
        assert totp.time_step == 30
        assert totp.last_verified_time_step is None
        assert len(totp.secret) == 32
        assert totp.enabled is False

    async def test_enroll_duplicate_identity(
        self, totp_factor: SQLAlchemyTOTPFactor, make_totp: MakeTOTPCallable
    ) -> None:
        identity_id = 123
        # Create an ENABLED enrollment to test duplicate protection
        await make_totp(identity_id=identity_id, enabled=True)

        with pytest.raises(AlreadyEnrolledTOTPException):
            await totp_factor.enroll(identity_id)

    async def test_enroll_replaces_disabled(
        self, totp_factor: SQLAlchemyTOTPFactor, make_totp: MakeTOTPCallable
    ) -> None:
        """Test that enrolling replaces a disabled enrollment (delete-on-re-enroll)."""
        identity_id = 123
        # Create a DISABLED enrollment
        await make_totp(identity_id=identity_id, enabled=False)

        # Should succeed - disabled enrollment is deleted and replaced
        new_enrollment = await totp_factor.enroll(identity_id)
        assert new_enrollment is not None
        assert new_enrollment.enabled is False


@pytest.mark.anyio
class TestTOTPEnable:
    async def test_enable_not_enrolled(self, totp_factor: SQLAlchemyTOTPFactor) -> None:
        with pytest.raises(NotEnrolledTOTPException):
            await totp_factor.enable(999, "123456")

    async def test_enable_with_valid_code(
        self, totp_factor: SQLAlchemyTOTPFactor, make_totp: MakeTOTPCallable
    ) -> None:
        totp = await make_totp(enabled=False)

        current_time = time.time()
        expected_code = totp._impl.generate(current_time).decode("ascii")
        updated_totp = await totp_factor.enable(totp.identity_id, expected_code)

        assert updated_totp.enabled is True

    async def test_enable_with_invalid_code(
        self, totp_factor: SQLAlchemyTOTPFactor, make_totp: MakeTOTPCallable
    ) -> None:
        totp = await make_totp(enabled=False)

        with pytest.raises(InvalidTOTPCodeException):
            await totp_factor.enable(totp.identity_id, "000000")

    async def test_enable_already_enabled(
        self, totp_factor: SQLAlchemyTOTPFactor, make_totp: MakeTOTPCallable
    ) -> None:
        totp = await make_totp(enabled=True)

        current_time = time.time()
        expected_code = totp._impl.generate(current_time).decode("ascii")
        with pytest.raises(AlreadyEnabledTOTPException):
            await totp_factor.enable(totp.identity_id, expected_code)


@pytest.mark.anyio
class TestTOTPVerify:
    async def test_not_enrolled(self, totp_factor: SQLAlchemyTOTPFactor) -> None:
        with pytest.raises(NotEnrolledTOTPException):
            await totp_factor.verify(999, "123456")

    async def test_not_enabled(
        self, totp_factor: SQLAlchemyTOTPFactor, make_totp: MakeTOTPCallable
    ) -> None:
        totp = await make_totp(enabled=False)

        with pytest.raises(NotEnabledTOTPException):
            await totp_factor.verify(totp.identity_id, "000000")

    async def test_invalid_code(
        self, totp_factor: SQLAlchemyTOTPFactor, make_totp: MakeTOTPCallable
    ) -> None:
        totp = await make_totp(enabled=True)

        with pytest.raises(InvalidTOTPCodeException):
            await totp_factor.verify(totp.identity_id, "000000")

    async def test_valid_code(
        self, totp_factor: SQLAlchemyTOTPFactor, make_totp: MakeTOTPCallable
    ) -> None:
        totp = await make_totp(enabled=True)

        current_time = time.time()
        expected_code = totp._impl.generate(current_time).decode("ascii")

        updated_totp = await totp_factor.verify(totp.identity_id, expected_code)
        assert updated_totp.last_verified_time_step is not None

    async def test_beyond_drift_tolerance(
        self, totp_factor: SQLAlchemyTOTPFactor, make_totp: MakeTOTPCallable
    ) -> None:
        totp = await make_totp(enabled=True)

        expected_code = totp._impl.generate(9999999999).decode("ascii")

        with pytest.raises(InvalidTOTPCodeException):
            await totp_factor.verify(totp.identity_id, expected_code)

    async def test_within_drift_tolerance(
        self, totp_factor: SQLAlchemyTOTPFactor, make_totp: MakeTOTPCallable
    ) -> None:
        totp = await make_totp(enabled=True)

        expected_code = totp._impl.generate(time.time() + 30).decode("ascii")

        updated_totp = await totp_factor.verify(totp.identity_id, expected_code)
        assert updated_totp.last_verified_time_step is not None

    async def test_replay_protection_same_time_step(
        self, totp_factor: SQLAlchemyTOTPFactor, make_totp: MakeTOTPCallable
    ) -> None:
        totp = await make_totp(enabled=True)

        current_time = int(time.time())
        expected_code = totp._impl.generate(current_time).decode("ascii")

        # First verification should succeed
        updated_totp = await totp_factor.verify(totp.identity_id, expected_code)
        assert updated_totp.last_verified_time_step is not None

        # Second verification with same code should fail (replay)
        with pytest.raises(InvalidTOTPCodeException):
            await totp_factor.verify(totp.identity_id, expected_code)

    async def test_replay_protection_previous_time_step(
        self, totp_factor: SQLAlchemyTOTPFactor, make_totp: MakeTOTPCallable
    ) -> None:
        totp = await make_totp(enabled=True)

        current_time = int(time.time())
        # Generate code for time step T-1
        past_time = current_time - totp.time_step
        past_code = totp._impl.generate(past_time).decode("ascii")

        # First verify current code to set last_verified_time_step
        current_code = totp._impl.generate(current_time).decode("ascii")
        await totp_factor.verify(totp.identity_id, current_code)

        # Now past code should be rejected
        with pytest.raises(InvalidTOTPCodeException):
            await totp_factor.verify(totp.identity_id, past_code)

    async def test_future_time_step_accepted(
        self, totp_factor: SQLAlchemyTOTPFactor, make_totp: MakeTOTPCallable
    ) -> None:
        totp = await make_totp(enabled=True)

        current_time = int(time.time())

        # Verify code at current time
        current_code = totp._impl.generate(current_time).decode("ascii")
        await totp_factor.verify(totp.identity_id, current_code)

        # Code from next time step should still work (within drift tolerance)
        next_time = current_time + totp.time_step
        next_code = totp._impl.generate(next_time).decode("ascii")
        updated_totp = await totp_factor.verify(totp.identity_id, next_code)
        assert updated_totp.last_verified_time_step is not None
