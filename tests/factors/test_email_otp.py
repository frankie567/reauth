import dataclasses
import typing
from collections.abc import AsyncGenerator

import pytest
from sqlalchemy import (
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

from reauth.factors.email_otp import (
    EmailOTP,
    EmailOTPEnrollment,
    EmailOTPFactor,
    ExpiredOTPException,
    InvalidOTPException,
)
from reauth.timestamp import get_current_timestamp
from reauth.tokens import HMACTokenVerifier, TokenVerifier

sqlalchemy_meta = MetaData()
email_otp_table = Table(
    "email_otps",
    sqlalchemy_meta,
    Column("id", Integer, primary_key=True),
    Column("code_verifier", String, nullable=False),
    Column("expires_at", Integer, nullable=False),
    Column("identity_id", Integer, nullable=False),
    Column("authentication_session_id", Integer, nullable=False, unique=True),
    Column("email", String, nullable=False),
    sqlite_autoincrement=True,
)


class SQLAlchemyEmailOTPFactor(EmailOTPFactor):
    """Concrete implementation of EmailOTPFactor using SQLAlchemy."""

    def __init__(
        self,
        connection: AsyncConnection,
        *,
        verifier: TokenVerifier,
        code_length: int = 6,
    ) -> None:
        self.connection = connection
        super().__init__(verifier=verifier, code_length=code_length)

    async def get_enrollment(self, identity_id: int) -> EmailOTPEnrollment | None:
        """Return a dummy enrollment for testing purposes."""
        return EmailOTPEnrollment(
            id=None, identity_id=identity_id, email="reauth@example.com"
        )

    async def insert(self, email_otp: EmailOTP) -> int:
        """Insert an EmailOTP into the database."""
        result = await self.connection.execute(
            insert(email_otp_table)
            .values(**dataclasses.asdict(email_otp))
            .returning(email_otp_table.c.id)
        )
        return result.scalar_one()

    async def get_by_id(self, otp_id: typing.Any) -> EmailOTP | None:
        """Retrieve an EmailOTP by its ID."""
        result = await self.connection.execute(
            select(email_otp_table).where(email_otp_table.c.id == otp_id)
        )
        row = result.fetchone()
        if row is None:
            return None
        return EmailOTP(**row._asdict())

    async def get_by_authentication_session_id(
        self, authentication_session_id: int
    ) -> EmailOTP | None:
        """Retrieve an EmailOTP by its authentication session ID."""
        result = await self.connection.execute(
            select(email_otp_table).where(
                email_otp_table.c.authentication_session_id
                == authentication_session_id,
            )
        )
        row = result.fetchone()
        if row is None:
            return None
        return EmailOTP(**row._asdict())

    async def delete(self, email_otp: EmailOTP) -> None:
        await self.connection.execute(
            delete(email_otp_table).where(email_otp_table.c.id == email_otp.id)
        )

    async def delete_by_authentication_session_id(
        self, authentication_session_id: int
    ) -> None:
        """Delete all EmailOTPs associated with a given authentication session ID."""
        await self.connection.execute(
            delete(email_otp_table).where(
                email_otp_table.c.authentication_session_id == authentication_session_id
            )
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
def email_otp_factor(
    sqlalchemy_connection: AsyncConnection,
) -> SQLAlchemyEmailOTPFactor:
    """Fixture that provides an instance of SQLAlchemyEmailOTPFactor."""
    return SQLAlchemyEmailOTPFactor(
        connection=sqlalchemy_connection,
        verifier=HMACTokenVerifier(current_key_id="test", keys={"test": b"t" * 32}),
        code_length=6,
    )


@pytest.mark.anyio
class TestEmailOTPCreate:
    async def test_returns_valid_otp(
        self, email_otp_factor: SQLAlchemyEmailOTPFactor
    ) -> None:
        identity_id = 123
        authentication_session_id = 456
        code, otp = await email_otp_factor.create(
            "reauth@example.com",
            authentication_session_id,
            identity_id=identity_id,
        )

        assert isinstance(code, str)
        assert len(code) == email_otp_factor.code_length
        assert isinstance(otp, EmailOTP)
        assert otp.id is not None
        assert otp.identity_id == identity_id
        assert otp.authentication_session_id == authentication_session_id
        assert otp.email == "reauth@example.com"
        assert not otp.is_expired()

    async def test_overrides_existing_otp(
        self, email_otp_factor: SQLAlchemyEmailOTPFactor
    ) -> None:
        identity_id = 123
        authentication_session_id = 456
        first_code, first_otp = await email_otp_factor.create(
            "reauth@example.com",
            authentication_session_id,
            identity_id=identity_id,
        )

        second_code, second_otp = await email_otp_factor.create(
            "reauth@example.com",
            authentication_session_id,
            identity_id=identity_id,
        )

        assert second_otp.id != first_otp.id
        assert second_code != first_code

        deleted_first_otp = await email_otp_factor.get_by_id(first_otp.id)
        assert deleted_first_otp is None

    async def test_otp_not_expired_immediately(
        self, email_otp_factor: SQLAlchemyEmailOTPFactor
    ) -> None:
        identity_id = 123
        authentication_session_id = 456
        _, otp = await email_otp_factor.create(
            "reauth@example.com",
            authentication_session_id,
            identity_id=identity_id,
        )
        assert not otp.is_expired()

    async def test_code_is_uppercase_alphanumeric(
        self, email_otp_factor: SQLAlchemyEmailOTPFactor
    ) -> None:
        identity_id = 123
        authentication_session_id = 456
        code, _ = await email_otp_factor.create(
            "reauth@example.com",
            authentication_session_id,
            identity_id=identity_id,
        )
        valid_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        assert all(c in valid_chars for c in code)


@pytest.mark.anyio
class TestEmailOTPConsume:
    async def test_invalid_code(
        self, email_otp_factor: SQLAlchemyEmailOTPFactor
    ) -> None:
        with pytest.raises(InvalidOTPException):
            await email_otp_factor.consume("INVALID_CODE", 123)

    async def test_invalid_authentication_session_id(
        self, email_otp_factor: SQLAlchemyEmailOTPFactor
    ) -> None:
        code = "ABC123"
        code_verifier = await email_otp_factor.verifier.create(code)
        identity_id = 123
        authentication_session_id = 456
        email_otp = EmailOTP(
            id=None,
            code_verifier=code_verifier,
            expires_at=get_current_timestamp() + 3600,
            identity_id=identity_id,
            authentication_session_id=authentication_session_id,
            email="reauth@example.com",
        )
        await email_otp_factor.insert(email_otp)
        with pytest.raises(InvalidOTPException):
            await email_otp_factor.consume(code, 789)

    async def test_expired_otp(
        self, email_otp_factor: SQLAlchemyEmailOTPFactor
    ) -> None:
        code = "ABC123"
        code_verifier = await email_otp_factor.verifier.create(code)
        identity_id = 123
        authentication_session_id = 456
        email_otp = EmailOTP(
            id=None,
            code_verifier=code_verifier,
            expires_at=0,  # Expired
            identity_id=identity_id,
            authentication_session_id=authentication_session_id,
            email="reauth@example.com",
        )
        await email_otp_factor.insert(email_otp)

        with pytest.raises(ExpiredOTPException):
            await email_otp_factor.consume(code, authentication_session_id)

    async def test_successful_consume(
        self, email_otp_factor: SQLAlchemyEmailOTPFactor
    ) -> None:
        code = "ABC123"
        code_verifier = await email_otp_factor.verifier.create(code)
        identity_id = 123
        authentication_session_id = 456
        email = "reauth@example.com"
        email_otp = EmailOTP(
            id=None,
            code_verifier=code_verifier,
            expires_at=get_current_timestamp() + 3600,
            identity_id=identity_id,
            authentication_session_id=authentication_session_id,
            email=email,
        )
        email_otp.id = await email_otp_factor.insert(email_otp)

        returned_identity_id, returned_email = await email_otp_factor.consume(
            code, authentication_session_id
        )
        assert returned_identity_id == identity_id
        assert returned_email == email

        # Verify that the OTP is deleted
        deleted_email_otp = await email_otp_factor.get_by_id(email_otp.id)
        assert deleted_email_otp is None
