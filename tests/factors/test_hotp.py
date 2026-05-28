import base64
import dataclasses
import secrets
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

from reauth.factors.hotp import (
    AlreadyEnabledHOTPException,
    AlreadyEnrolledHOTPException,
    HOTPEnrollment,
    HOTPFactor,
    InvalidHOTPCodeException,
    NotEnabledHOTPException,
    NotEnrolledHOTPException,
)

sqlalchemy_meta = MetaData()
hotp_table = Table(
    "hotps",
    sqlalchemy_meta,
    Column("id", Integer, primary_key=True),
    Column("identity_id", Integer, nullable=False),
    Column("enabled", Integer, nullable=False, default=0),
    Column("secret", String(32), nullable=False),
    Column("algorithm", String(4), nullable=False),
    Column("code_length", Integer, nullable=False),
    Column("counter", Integer, nullable=False),
    sqlite_autoincrement=True,
)


class SQLAlchemyHOTPFactor(HOTPFactor):
    """Concrete implementation of HOTPFactor using SQLAlchemy."""

    def __init__(self, connection: AsyncConnection) -> None:
        self.connection = connection
        super().__init__()

    async def get_by_identity_id(self, identity_id: int) -> HOTPEnrollment | None:
        """Retrieve the HOTP enrollment for a given identity, regardless of enabled state."""
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

    async def delete(self, hotp: HOTPEnrollment) -> None:
        """Delete an HOTP from the database."""
        await self.connection.execute(
            hotp_table.delete().where(hotp_table.c.id == hotp.id)
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


class MakeHOTPCallable(typing.Protocol):
    async def __call__(
        self, identity_id: int = 123, enabled: bool = False, counter: int = 0
    ) -> HOTPEnrollment: ...


@pytest.fixture
def make_hotp(
    hotp_factor: SQLAlchemyHOTPFactor,
) -> MakeHOTPCallable:
    """Factory fixture to create HOTPEnrollment instances with optional enabled state."""

    async def _make_hotp(
        identity_id: int = 123, enabled: bool = False, counter: int = 0
    ) -> HOTPEnrollment:
        secret = secrets.token_bytes(20)
        hotp = HOTPEnrollment(
            id=None,
            identity_id=identity_id,
            enabled=enabled,
            secret=base64.b32encode(secret).decode("ascii"),
            algorithm="sha1",
            code_length=6,
            counter=counter,
        )
        hotp.id = await hotp_factor.insert(hotp)
        return hotp

    return _make_hotp


class TestHOTP:
    def test_get_provisioning_uri(self) -> None:
        secret = secrets.token_bytes(20)  # 160-bit secret key
        base64.b32encode(secret).decode("ascii")
        hotp = HOTPEnrollment(
            id=1,
            identity_id=123,
            enabled=True,
            secret=base64.b32encode(secret).decode("ascii"),
            algorithm="sha1",
            code_length=6,
            counter=0,
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
        assert hotp.enabled is False

    async def test_enroll_duplicate_identity(
        self, hotp_factor: SQLAlchemyHOTPFactor, make_hotp: MakeHOTPCallable
    ) -> None:
        identity_id = 123
        # Create an ENABLED enrollment to test duplicate protection
        await make_hotp(identity_id=identity_id, enabled=True)

        with pytest.raises(AlreadyEnrolledHOTPException):
            await hotp_factor.enroll(identity_id)

    async def test_enroll_replaces_disabled(
        self, hotp_factor: SQLAlchemyHOTPFactor, make_hotp: MakeHOTPCallable
    ) -> None:
        """Test that enrolling replaces a disabled enrollment (delete-on-re-enroll)."""
        identity_id = 123
        # Create a DISABLED enrollment
        await make_hotp(identity_id=identity_id, enabled=False)

        # Should succeed - disabled enrollment is deleted and replaced
        new_enrollment = await hotp_factor.enroll(identity_id)
        assert new_enrollment is not None
        assert new_enrollment.enabled is False


@pytest.mark.anyio
class TestHOTPEnable:
    async def test_enable_not_enrolled(self, hotp_factor: SQLAlchemyHOTPFactor) -> None:
        with pytest.raises(NotEnrolledHOTPException):
            await hotp_factor.enable(999, "123456")

    async def test_enable_with_valid_code(
        self, hotp_factor: SQLAlchemyHOTPFactor, make_hotp: MakeHOTPCallable
    ) -> None:
        hotp = await make_hotp(enabled=False)

        expected_code = hotp._impl.generate(hotp.counter).decode("ascii")
        updated_hotp = await hotp_factor.enable(hotp.identity_id, expected_code)

        assert updated_hotp.enabled is True
        assert updated_hotp.counter == 1

    async def test_enable_with_invalid_code(
        self, hotp_factor: SQLAlchemyHOTPFactor, make_hotp: MakeHOTPCallable
    ) -> None:
        hotp = await make_hotp(enabled=False)

        with pytest.raises(InvalidHOTPCodeException):
            await hotp_factor.enable(hotp.identity_id, "000000")

    async def test_enable_already_enabled(
        self, hotp_factor: SQLAlchemyHOTPFactor, make_hotp: MakeHOTPCallable
    ) -> None:
        hotp = await make_hotp(enabled=True)

        with pytest.raises(AlreadyEnabledHOTPException):
            await hotp_factor.enable(
                hotp.identity_id, hotp._impl.generate(hotp.counter).decode("ascii")
            )


@pytest.mark.anyio
class TestHOTPVerify:
    async def test_not_enrolled(self, hotp_factor: SQLAlchemyHOTPFactor) -> None:
        with pytest.raises(NotEnrolledHOTPException):
            await hotp_factor.verify(999, "123456")

    async def test_not_enabled(
        self, hotp_factor: SQLAlchemyHOTPFactor, make_hotp: MakeHOTPCallable
    ) -> None:
        hotp = await make_hotp(enabled=False)

        with pytest.raises(NotEnabledHOTPException):
            await hotp_factor.verify(hotp.identity_id, "000000")

    async def test_invalid_code(
        self, hotp_factor: SQLAlchemyHOTPFactor, make_hotp: MakeHOTPCallable
    ) -> None:
        hotp = await make_hotp(enabled=True)

        with pytest.raises(InvalidHOTPCodeException):
            await hotp_factor.verify(hotp.identity_id, "000000")

    async def test_valid_code(
        self, hotp_factor: SQLAlchemyHOTPFactor, make_hotp: MakeHOTPCallable
    ) -> None:
        hotp = await make_hotp(enabled=True)

        expected_code = hotp._impl.generate(hotp.counter).decode("ascii")

        updated_hotp = await hotp_factor.verify(hotp.identity_id, expected_code)

        assert updated_hotp.counter == 1

    async def test_beyond_lookahead(
        self, hotp_factor: SQLAlchemyHOTPFactor, make_hotp: MakeHOTPCallable
    ) -> None:
        hotp = await make_hotp(enabled=True)

        expected_code = hotp._impl.generate(hotp.counter + 10).decode("ascii")

        with pytest.raises(InvalidHOTPCodeException):
            await hotp_factor.verify(hotp.identity_id, expected_code)

    async def test_valid_code_desync(
        self, hotp_factor: SQLAlchemyHOTPFactor, make_hotp: MakeHOTPCallable
    ) -> None:
        hotp = await make_hotp(enabled=True)

        expected_code = hotp._impl.generate(hotp.counter + 4).decode("ascii")

        updated_hotp = await hotp_factor.verify(hotp.identity_id, expected_code)

        assert updated_hotp.counter == 5
