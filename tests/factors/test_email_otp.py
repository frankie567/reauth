import dataclasses
import typing
from collections.abc import AsyncGenerator

import pytest
import sqlalchemy
from sqlalchemy import (
    MetaData,
    insert,
)
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from reauth.authentication_session import AuthenticationSession
from reauth.factors.email_otp import (
    EmailOTP,
    EmailOTPEnrollment,
    ExpiredOTPException,
    InvalidOTPException,
)
from reauth.integrations.sqlalchemy import (
    SQLAlchemyEmailOTPFactor,
    create_authentication_session_table,
    create_email_otp_table,
)
from reauth.timestamp import get_current_timestamp
from reauth.tokens import HMACTokenVerifier

sqlalchemy_meta = MetaData()
email_otp_table = create_email_otp_table(sqlalchemy_meta)
users_table = sqlalchemy.Table(
    "users",
    sqlalchemy_meta,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("email", sqlalchemy.Text, nullable=False),
)
authentication_session_table = create_authentication_session_table(sqlalchemy_meta)


class UserEmailOTPFactor(SQLAlchemyEmailOTPFactor):
    async def get_enrollment(
        self, identity_id: typing.Any
    ) -> EmailOTPEnrollment | None:
        self._require_transaction()
        result = await self.connection.execute(
            sqlalchemy.select(users_table.c.id, users_table.c.email)
            .where(users_table.c.id == identity_id)
            .with_for_update()
        )
        row = result.mappings().one_or_none()
        if row is None:
            return None
        return EmailOTPEnrollment(
            id=row["id"], identity_id=row["id"], email=row["email"]
        )


@pytest.fixture
async def sqlalchemy_connection(
    sqlalchemy_integration_engine: AsyncEngine,
) -> AsyncGenerator[AsyncConnection]:
    """Fixture that creates tables and provides a connection for testing."""
    async with sqlalchemy_integration_engine.begin() as conn:
        await conn.run_sync(sqlalchemy_meta.create_all)
        await conn.execute(
            insert(authentication_session_table).values(
                **dataclasses.asdict(
                    AuthenticationSession(
                        id=456,
                        token_identifier="test",
                        token_verifier="test",
                        expires_at=0,
                        identity_id=None,
                    )
                )
            )
        )
        yield conn
        await conn.run_sync(sqlalchemy_meta.drop_all)


@pytest.fixture
def email_otp_factor(
    sqlalchemy_connection: AsyncConnection,
) -> SQLAlchemyEmailOTPFactor:
    """Fixture that provides an instance of SQLAlchemyEmailOTPFactor."""
    return UserEmailOTPFactor(
        connection=sqlalchemy_connection,
        table=email_otp_table,
        authentication_session_table=authentication_session_table,
        verifier=HMACTokenVerifier(current_key_id="test", keys={"test": b"t" * 32}),
        code_length=6,
    )


@pytest.mark.anyio
class TestEmailOTPCreate:
    @pytest.mark.parametrize("identity_id", [None, 123])
    async def test_returns_valid_otp(
        self, email_otp_factor: SQLAlchemyEmailOTPFactor, identity_id: int | None
    ) -> None:
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
        first_otp = EmailOTP(
            id=42,
            identity_id=identity_id,
            authentication_session_id=authentication_session_id,
            email="reauth@example.com",
            code_verifier=await email_otp_factor.verifier.create("ABC123"),
            expires_at=get_current_timestamp() + 3600,
        )
        await email_otp_factor.connection.execute(
            insert(email_otp_table).values(**dataclasses.asdict(first_otp))
        )

        second_code, second_otp = await email_otp_factor.create(
            "reauth@example.com",
            authentication_session_id,
            identity_id=identity_id,
        )

        assert (
            await email_otp_factor.get_by_authentication_session_id(
                authentication_session_id
            )
            == second_otp
        )
        assert await email_otp_factor.verifier.verify_and_update(
            second_code, second_otp.code_verifier
        ) == (True, None)
        assert second_otp.code_verifier != first_otp.code_verifier

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
            id=42,
            code_verifier=code_verifier,
            expires_at=get_current_timestamp() + 3600,
            identity_id=identity_id,
            authentication_session_id=authentication_session_id,
            email="reauth@example.com",
        )
        await email_otp_factor.connection.execute(
            insert(email_otp_table).values(**dataclasses.asdict(email_otp))
        )
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
            id=42,
            code_verifier=code_verifier,
            expires_at=0,  # Expired
            identity_id=identity_id,
            authentication_session_id=authentication_session_id,
            email="reauth@example.com",
        )
        await email_otp_factor.connection.execute(
            insert(email_otp_table).values(**dataclasses.asdict(email_otp))
        )

        with pytest.raises(ExpiredOTPException):
            await email_otp_factor.consume(code, authentication_session_id)

    @pytest.mark.parametrize("identity_id", [None, 123])
    async def test_successful_consume(
        self, email_otp_factor: SQLAlchemyEmailOTPFactor, identity_id: int | None
    ) -> None:
        code = "ABC123"
        code_verifier = await email_otp_factor.verifier.create(code)
        authentication_session_id = 456
        email = "reauth@example.com"
        email_otp = EmailOTP(
            id=42,
            code_verifier=code_verifier,
            expires_at=get_current_timestamp() + 3600,
            identity_id=identity_id,
            authentication_session_id=authentication_session_id,
            email=email,
        )
        await email_otp_factor.connection.execute(
            insert(email_otp_table).values(**dataclasses.asdict(email_otp))
        )

        returned_identity_id, returned_email = await email_otp_factor.consume(
            code, authentication_session_id
        )
        assert returned_identity_id == identity_id
        assert returned_email == email

        # Verify that the OTP is deleted
        assert (
            await email_otp_factor.get_by_authentication_session_id(
                authentication_session_id
            )
            is None
        )
