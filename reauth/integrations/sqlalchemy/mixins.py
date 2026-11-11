"""Shared SQLAlchemy adapter behavior."""

import dataclasses
import typing

import sqlalchemy
import sqlalchemy.exc
import sqlalchemy.ext.asyncio

from reauth.factors import EnrollmentCollision
from reauth.factors.hotp import HOTPEnrollment
from reauth.factors.totp import TOTPEnrollment
from reauth.integrations.sqlalchemy.exceptions import (
    MissingTransactionException,
)


class TransactionMixin:
    """Require a caller-owned transaction on the adapter's connection."""

    connection: sqlalchemy.ext.asyncio.AsyncConnection

    def _require_transaction(self) -> None:
        if not self.connection.in_transaction():
            raise MissingTransactionException()


class OTPEnrollmentMixin[ENROLLMENT: HOTPEnrollment | TOTPEnrollment](TransactionMixin):
    """Persist OTP enrollments within a caller-owned transaction."""

    table: sqlalchemy.Table
    enrollment_type: type[ENROLLMENT]

    async def get_by_identity_id(self, identity_id: typing.Any) -> ENROLLMENT | None:
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
                    for field in dataclasses.fields(self.enrollment_type)
                )
            )
            .where(self.table.c.identity_id == identity_id)
            .with_for_update()
        )
        row = result.mappings().one_or_none()
        return self.enrollment_type(**row) if row is not None else None

    async def _insert_enrollment(self, enrollment: ENROLLMENT) -> typing.Any:
        """
        Insert an enrollment without committing the caller's transaction.

        Returns:
            The inserted record ID.

        Raises:
            EnrollmentCollision: If this identity already has an
                enrollment. The caller's transaction remains usable.
            sqlalchemy.exc.IntegrityError: If another integrity constraint fails.
        """
        self._require_transaction()
        values = dataclasses.asdict(enrollment)
        if enrollment.id is None:
            del values["id"]
        try:
            async with self.connection.begin_nested():
                result = await self.connection.execute(
                    sqlalchemy.insert(self.table).values(**values)
                )
                primary_key = result.inserted_primary_key
                assert primary_key is not None
                return primary_key[0]
        except sqlalchemy.exc.IntegrityError as error:
            existing_id = await self.connection.scalar(
                sqlalchemy.select(self.table.c.id)
                .where(self.table.c.identity_id == enrollment.identity_id)
                .with_for_update()
            )
            if existing_id is not None:
                raise EnrollmentCollision() from error
            raise

    async def _update_enrollment(self, enrollment: ENROLLMENT) -> None:
        """Update a previously protected enrollment without committing."""
        self._require_transaction()
        values = dataclasses.asdict(enrollment)
        del values["id"]
        await self.connection.execute(
            sqlalchemy.update(self.table)
            .where(self.table.c.id == enrollment.id)
            .values(**values)
        )

    async def _delete_enrollment(self, enrollment: ENROLLMENT) -> None:
        """Delete a previously protected enrollment without committing."""
        self._require_transaction()
        await self.connection.execute(
            sqlalchemy.delete(self.table).where(self.table.c.id == enrollment.id)
        )
