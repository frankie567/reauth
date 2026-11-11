"""HOTP enrollment storage using SQLAlchemy Core."""

import typing

import sqlalchemy
import sqlalchemy.ext.asyncio

from reauth.factors.hotp import HOTPAlgorithm, HOTPEnrollment, HOTPFactor
from reauth.integrations.sqlalchemy.mixins import OTPEnrollmentMixin


def create_hotp_enrollment_table(
    metadata: sqlalchemy.MetaData,
    *,
    name: str = "hotp_enrollments",
    id_type: sqlalchemy.types.TypeEngine[typing.Any]
    | type[sqlalchemy.types.TypeEngine[typing.Any]] = sqlalchemy.Integer,
    identity_id_type: sqlalchemy.types.TypeEngine[typing.Any]
    | type[sqlalchemy.types.TypeEngine[typing.Any]] = sqlalchemy.Integer,
) -> sqlalchemy.Table:
    """
    Define an HOTP enrollment table without creating it in the database.

    Args:
        metadata: Application-owned metadata, including any schema configuration.
        name: The table name. Use a separate table for each configured factor.
        id_type: The enrollment ID type. Supply a custom table for non-integer ID defaults.
        identity_id_type: The application's identity ID type.

    Returns:
        The table registered in the supplied metadata. Applications own migrations.
    """
    return sqlalchemy.Table(
        name,
        metadata,
        sqlalchemy.Column("id", id_type, primary_key=True),
        sqlalchemy.Column("identity_id", identity_id_type, nullable=False, unique=True),
        sqlalchemy.Column("enabled", sqlalchemy.Boolean, nullable=False),
        sqlalchemy.Column("secret", sqlalchemy.Text, nullable=False),
        sqlalchemy.Column("algorithm", sqlalchemy.String(16), nullable=False),
        sqlalchemy.Column("code_length", sqlalchemy.Integer, nullable=False),
        sqlalchemy.Column("counter", sqlalchemy.BigInteger, nullable=False),
    )


class SQLAlchemyHOTPFactor(OTPEnrollmentMixin[HOTPEnrollment], HOTPFactor):
    """Store HOTP enrollments within a caller-owned SQLAlchemy transaction."""

    enrollment_type = HOTPEnrollment

    def __init__(
        self,
        connection: sqlalchemy.ext.asyncio.AsyncConnection,
        table: sqlalchemy.Table,
        *,
        code_length: int = 6,
        algorithm: HOTPAlgorithm = "sha1",
        look_ahead: int = 5,
        identifier: str = "hotp",
        step: int = 1,
        advance_by: int = 1,
    ) -> None:
        """
        Initialize HOTP enrollment storage.

        Args:
            connection: A connection with an active transaction. Do not use DBAPI
                autocommit. Keep the transaction open throughout each operation.
            table: A table dedicated to this configured factor, containing the
                HOTPEnrollment fields, a primary key on id, and a non-deferrable
                unique constraint on identity_id. Secrets are stored as plaintext.
            code_length: The number of digits in generated codes.
            algorithm: The algorithm used for new enrollments.
            look_ahead: The number of future counters accepted during verification.
            identifier: The configured factor identifier.
            step: The authentication step at which this factor is available.
            advance_by: The number of authentication steps advanced on success.

        Raises:
            MissingTransactionException: If the connection has no active transaction.
        """  # noqa: DOC502
        self.connection = connection
        self._require_transaction()
        self.table = table
        super().__init__(
            code_length=code_length,
            algorithm=algorithm,
            look_ahead=look_ahead,
            identifier=identifier,
            step=step,
            advance_by=advance_by,
        )

    async def insert(self, hotp: HOTPEnrollment) -> typing.Any:
        return await self._insert_enrollment(hotp)

    async def update(self, hotp: HOTPEnrollment) -> None:
        await self._update_enrollment(hotp)

    async def delete(self, hotp: HOTPEnrollment) -> None:
        await self._delete_enrollment(hotp)
