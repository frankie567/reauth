"""Backup codes enrollment storage using SQLAlchemy Core."""

import typing

import sqlalchemy
import sqlalchemy.ext.asyncio

from reauth.factors.backup_codes import (
    DEFAULT_CHARS,
    BackupCodesEnrollment,
    BackupCodesFactor,
)
from reauth.integrations.sqlalchemy.mixins import OTPEnrollmentMixin
from reauth.tokens import TokenVerifier


def create_backup_codes_enrollment_table(
    metadata: sqlalchemy.MetaData,
    *,
    name: str = "backup_codes_enrollments",
    id_type: sqlalchemy.types.TypeEngine[typing.Any]
    | type[sqlalchemy.types.TypeEngine[typing.Any]] = sqlalchemy.Integer,
    identity_id_type: sqlalchemy.types.TypeEngine[typing.Any]
    | type[sqlalchemy.types.TypeEngine[typing.Any]] = sqlalchemy.Integer,
) -> sqlalchemy.Table:
    """
    Define a backup codes enrollment table without creating it in the database.

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
        sqlalchemy.Column("codes", sqlalchemy.JSON, nullable=False),
        sqlalchemy.Column("used_codes", sqlalchemy.JSON, nullable=False),
    )


class SQLAlchemyBackupCodesFactor(
    OTPEnrollmentMixin[BackupCodesEnrollment], BackupCodesFactor
):
    """Store backup codes within a caller-owned SQLAlchemy transaction."""

    enrollment_type = BackupCodesEnrollment

    def __init__(
        self,
        connection: sqlalchemy.ext.asyncio.AsyncConnection,
        table: sqlalchemy.Table,
        *,
        verifier: TokenVerifier,
        code_length: int = 10,
        code_count: int = 10,
        chars: str = DEFAULT_CHARS,
        identifier: str = "backup_codes",
        step: int = 1,
        advance_by: int = 1,
    ) -> None:
        """
        Initialize backup codes enrollment storage.

        Args:
            connection: A connection with an active transaction. Do not use DBAPI
                autocommit. Keep the transaction open throughout each operation.
            table: A table dedicated to this configured factor, containing the
                BackupCodesEnrollment fields, a primary key on id, and a
                non-deferrable unique constraint on identity_id. Code verifiers and
                used-code tracking are stored as JSON lists.
            verifier: Code verification and key rotation.
            code_length: The number of characters in generated backup codes.
            code_count: The number of codes generated for each enrollment.
            chars: The character set for code generation.
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
            verifier=verifier,
            code_length=code_length,
            code_count=code_count,
            chars=chars,
            identifier=identifier,
            step=step,
            advance_by=advance_by,
        )

    async def get_enrollment(
        self, identity_id: typing.Any
    ) -> BackupCodesEnrollment | None:
        return await self.get_by_identity_id(identity_id)

    async def insert(self, backup_codes: BackupCodesEnrollment) -> typing.Any:
        return await self._insert_enrollment(backup_codes)

    async def update(self, backup_codes: BackupCodesEnrollment) -> None:
        await self._update_enrollment(backup_codes)

    async def delete(self, backup_codes: BackupCodesEnrollment) -> None:
        await self._delete_enrollment(backup_codes)
