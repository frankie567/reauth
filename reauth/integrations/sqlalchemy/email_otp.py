"""Email OTP storage using SQLAlchemy Core."""

import dataclasses
import datetime
import typing

import sqlalchemy
import sqlalchemy.ext.asyncio

from reauth.factors.email_otp import EmailOTP, EmailOTPFactor
from reauth.integrations.sqlalchemy.exceptions import ReauthSQLAlchemyException
from reauth.integrations.sqlalchemy.mixins import TransactionMixin
from reauth.tokens import TokenVerifier


class AuthenticationSessionNotFoundException(ReauthSQLAlchemyException):
    """Raised when OTP creation cannot protect a missing parent session."""


def create_email_otp_table(
    metadata: sqlalchemy.MetaData,
    *,
    name: str = "email_otps",
    id_type: sqlalchemy.types.TypeEngine[typing.Any]
    | type[sqlalchemy.types.TypeEngine[typing.Any]] = sqlalchemy.Integer,
    identity_id_type: sqlalchemy.types.TypeEngine[typing.Any]
    | type[sqlalchemy.types.TypeEngine[typing.Any]] = sqlalchemy.Integer,
    authentication_session_id_type: sqlalchemy.types.TypeEngine[typing.Any]
    | type[sqlalchemy.types.TypeEngine[typing.Any]] = sqlalchemy.Integer,
) -> sqlalchemy.Table:
    """
    Define a pending email OTP table without creating it in the database.

    Args:
        metadata: Application-owned metadata, including any schema configuration.
        name: The table name. Use a separate table for each configured factor.
        id_type: The OTP ID type. Supply a custom table for non-integer ID defaults.
        identity_id_type: The application's identity ID type.
        authentication_session_id_type: The authentication session ID type.

    Returns:
        The table registered in the supplied metadata. Applications own migrations.
    """
    return sqlalchemy.Table(
        name,
        metadata,
        sqlalchemy.Column("id", id_type, primary_key=True),
        sqlalchemy.Column("identity_id", identity_id_type, nullable=True),
        sqlalchemy.Column("email", sqlalchemy.Text, nullable=False),
        sqlalchemy.Column("code_verifier", sqlalchemy.Text, nullable=False),
        sqlalchemy.Column("expires_at", sqlalchemy.BigInteger, nullable=False),
        sqlalchemy.Column(
            "authentication_session_id",
            authentication_session_id_type,
            nullable=False,
            unique=True,
        ),
    )


class SQLAlchemyEmailOTPFactor(TransactionMixin, EmailOTPFactor):
    """
    Store pending email OTPs within a caller-owned SQLAlchemy transaction.

    Subclass and implement get_enrollment to resolve an EmailOTPEnrollment from
    application data, such as a users table, under transaction-long protection.
    """

    def __init__(
        self,
        connection: sqlalchemy.ext.asyncio.AsyncConnection,
        table: sqlalchemy.Table,
        *,
        authentication_session_table: sqlalchemy.Table,
        verifier: TokenVerifier,
        code_length: int = 6,
        lifetime: datetime.timedelta = datetime.timedelta(minutes=10),
        identifier: str = "email_otp",
        step: int = 0,
        advance_by: int = 1,
    ) -> None:
        """
        Initialize email OTP storage.

        Args:
            connection: A connection with an active transaction. Do not use DBAPI
                autocommit. Keep the transaction open throughout each operation.
            table: A table dedicated to this factor containing the EmailOTP fields,
                a primary key on id, and a non-deferrable unique constraint on
                authentication_session_id. identity_id must allow NULL for signup.
            authentication_session_table: The parent authentication session table,
                with a primary key on id. Parent rows must exist before OTP creation.
                Always lock parent sessions before OTP rows.
            verifier: OTP code hashing and verification.
            code_length: The number of characters in generated codes.
            lifetime: The OTP lifetime.
            identifier: The configured factor identifier.
            step: The authentication step at which this factor is available.
            advance_by: The number of authentication steps advanced on success.

        Raises:
            MissingTransactionException: If the connection has no active transaction.
        """  # noqa: DOC502
        self.connection = connection
        self._require_transaction()
        self.table = table
        self.authentication_session_table = authentication_session_table
        super().__init__(
            verifier=verifier,
            code_length=code_length,
            lifetime=lifetime,
            identifier=identifier,
            step=step,
            advance_by=advance_by,
        )

    async def insert(self, email_otp: EmailOTP) -> typing.Any:
        """
        Insert an OTP under parent session protection without committing.

        Returns:
            The inserted record ID.

        Raises:
            AuthenticationSessionNotFoundException: If the parent session is missing.
        """
        self._require_transaction()
        if not await self._lock_authentication_session(
            email_otp.authentication_session_id
        ):
            raise AuthenticationSessionNotFoundException()
        values = dataclasses.asdict(email_otp)
        if email_otp.id is None:
            del values["id"]
        result = await self.connection.execute(
            sqlalchemy.insert(self.table).values(**values)
        )
        primary_key = result.inserted_primary_key
        assert primary_key is not None
        return primary_key[0]

    async def get_by_authentication_session_id(
        self, authentication_session_id: typing.Any
    ) -> EmailOTP | None:
        """
        Read an OTP, including expired ones, under a transaction-long lock.

        Returns:
            The OTP, or None if it or its parent session does not exist.
        """
        self._require_transaction()
        if not await self._lock_authentication_session(authentication_session_id):
            return None
        result = await self.connection.execute(
            sqlalchemy.select(
                *(self.table.c[field.name] for field in dataclasses.fields(EmailOTP))
            )
            .where(self.table.c.authentication_session_id == authentication_session_id)
            .with_for_update()
        )
        row = result.mappings().one_or_none()
        return EmailOTP(**row) if row is not None else None

    async def delete(self, email_otp: EmailOTP) -> None:
        """Delete a previously protected OTP without committing."""
        self._require_transaction()
        await self.connection.execute(
            sqlalchemy.delete(self.table).where(self.table.c.id == email_otp.id)
        )

    async def delete_by_authentication_session_id(
        self, authentication_session_id: typing.Any
    ) -> None:
        """
        Protect the parent session before deleting pending OTPs, without committing.

        Raises:
            AuthenticationSessionNotFoundException: If the parent session is missing.
        """
        self._require_transaction()
        if not await self._lock_authentication_session(authentication_session_id):
            raise AuthenticationSessionNotFoundException()
        await self.connection.execute(
            sqlalchemy.delete(self.table).where(
                self.table.c.authentication_session_id == authentication_session_id
            )
        )

    async def _lock_authentication_session(
        self, authentication_session_id: typing.Any
    ) -> bool:
        session_id = await self.connection.scalar(
            sqlalchemy.select(self.authentication_session_table.c.id)
            .where(self.authentication_session_table.c.id == authentication_session_id)
            .with_for_update()
        )
        return session_id is not None
