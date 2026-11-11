"""TOTP enrollment storage using SQLAlchemy Core."""

import dataclasses
import typing

import sqlalchemy
import sqlalchemy.ext.asyncio

from reauth.factors.totp import TOTPAlgorithm, TOTPEnrollment, TOTPFactor
from reauth.integrations.sqlalchemy.mixins import TransactionMixin


def create_totp_enrollment_table(
    metadata: sqlalchemy.MetaData,
    *,
    name: str = "totp_enrollments",
    id_type: sqlalchemy.types.TypeEngine[typing.Any]
    | type[sqlalchemy.types.TypeEngine[typing.Any]] = sqlalchemy.Integer,
    identity_id_type: sqlalchemy.types.TypeEngine[typing.Any]
    | type[sqlalchemy.types.TypeEngine[typing.Any]] = sqlalchemy.Integer,
) -> sqlalchemy.Table:
    """
    Define a TOTP enrollment table without creating it in the database.

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
        sqlalchemy.Column("time_step", sqlalchemy.Integer, nullable=False),
        sqlalchemy.Column(
            "last_verified_time_step", sqlalchemy.BigInteger, nullable=True
        ),
    )


class SQLAlchemyTOTPFactor(TransactionMixin, TOTPFactor):
    """Store TOTP enrollments within a caller-owned SQLAlchemy transaction."""

    def __init__(
        self,
        connection: sqlalchemy.ext.asyncio.AsyncConnection,
        table: sqlalchemy.Table,
        *,
        code_length: int = 6,
        algorithm: TOTPAlgorithm = "sha256",
        time_step: int = 30,
        drift_tolerance: int = 1,
        identifier: str = "totp",
        step: int = 1,
        advance_by: int = 1,
    ) -> None:
        """
        Initialize TOTP enrollment storage.

        Args:
            connection: A connection with an active transaction. Do not use DBAPI
                autocommit. Keep the transaction open throughout each operation.
            table: A table dedicated to this configured factor, containing the
                TOTPEnrollment fields, a primary key on id, and a non-deferrable
                unique constraint on identity_id. Secrets are stored as plaintext.
            code_length: The number of digits in generated codes.
            algorithm: The algorithm used for new enrollments.
            time_step: The number of seconds per time step for new enrollments.
            drift_tolerance: The number of time steps accepted on either side of now.
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
            time_step=time_step,
            drift_tolerance=drift_tolerance,
            identifier=identifier,
            step=step,
            advance_by=advance_by,
        )

    async def get_by_identity_id(
        self, identity_id: typing.Any
    ) -> TOTPEnrollment | None:
        """
        Read an enrollment, including disabled ones, under a transaction-long lock.

        Args:
            identity_id: The identity whose enrollment to retrieve.

        Returns:
            The stored enrollment, or None if it does not exist.
        """
        self._require_transaction()
        result = await self.connection.execute(
            sqlalchemy.select(
                *(
                    self.table.c[field.name]
                    for field in dataclasses.fields(TOTPEnrollment)
                )
            )
            .where(self.table.c.identity_id == identity_id)
            .with_for_update()
        )
        row = result.mappings().one_or_none()
        return TOTPEnrollment(**row) if row is not None else None

    async def insert(self, totp: TOTPEnrollment) -> typing.Any:
        """
        Insert an enrollment without committing the caller's transaction.

        Returns:
            The inserted record ID.
        """
        self._require_transaction()
        values = dataclasses.asdict(totp)
        if totp.id is None:
            del values["id"]
        result = await self.connection.execute(
            sqlalchemy.insert(self.table).values(**values)
        )
        primary_key = result.inserted_primary_key
        assert primary_key is not None
        return primary_key[0]

    async def update(self, totp: TOTPEnrollment) -> None:
        """Update a previously protected enrollment without committing."""
        self._require_transaction()
        values = dataclasses.asdict(totp)
        del values["id"]
        await self.connection.execute(
            sqlalchemy.update(self.table)
            .where(self.table.c.id == totp.id)
            .values(**values)
        )

    async def delete(self, totp: TOTPEnrollment) -> None:
        """Delete a previously protected enrollment without committing."""
        self._require_transaction()
        await self.connection.execute(
            sqlalchemy.delete(self.table).where(self.table.c.id == totp.id)
        )
