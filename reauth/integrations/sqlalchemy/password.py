"""Password storage on an application-owned identity table."""

import dataclasses
import datetime
import typing

import sqlalchemy
import sqlalchemy.exc
import sqlalchemy.ext.asyncio

from reauth.factors.password import PasswordEnrollment, PasswordFactor, PasswordHash
from reauth.integrations.sqlalchemy.mixins import TransactionMixin
from reauth.tokens import TokenIdentifierCollision, TokenProvider


class SQLAlchemyPasswordFactor(TransactionMixin, PasswordFactor):
    """Store password state on identities within a caller-owned transaction."""

    def __init__(
        self,
        connection: sqlalchemy.ext.asyncio.AsyncConnection,
        table: sqlalchemy.Table,
        *,
        token_provider: TokenProvider,
        password_hash: PasswordHash | None = None,
        reset_lifetime: datetime.timedelta = datetime.timedelta(minutes=30),
        identifier: str = "password",
        step: int = 0,
        advance_by: int = 1,
    ) -> None:
        """Initialize password storage.

        Args:
            connection: A connection with an active transaction. Do not use DBAPI
                autocommit. Keep the transaction open throughout each operation.
            table: Application-owned identity table with a primary key on id and
                nullable password_hash, reset_token_identifier, reset_token_verifier,
                and reset_token_expires_at columns. Enforce a non-deferrable unique
                constraint on non-null reset identifiers. These columns belong to
                one configured password factor. All writers must protect the identity
                row before reading or changing password state. The application owns
                identity creation, deletion, and migrations.
            token_provider: Reset token generation, parsing, and verification.
            password_hash: Synchronous hashing backend; defaults to pwdlib.
            reset_lifetime: Reset token lifetime.
            identifier: Unique identifier for this configured factor.
            step: Authentication step at which this factor is available.
            advance_by: Number of authentication steps advanced on success.

        Raises:
            MissingTransactionException: If the connection has no active transaction.
        """  # noqa: DOC502
        self.connection = connection
        self._require_transaction()
        self.table = table
        super().__init__(
            token_provider=token_provider,
            password_hash=password_hash,
            reset_lifetime=reset_lifetime,
            identifier=identifier,
            step=step,
            advance_by=advance_by,
        )

    async def get_by_identity_id(
        self, identity_id: typing.Any
    ) -> PasswordEnrollment | None:
        """Read password state under an identity row lock.

        Args:
            identity_id: The identity ID to match.

        Returns:
            Password state, including an unset password, or None for a missing identity.
        """
        return await self._get(self.table.c.id == identity_id)

    async def get_by_reset_token_identifier(
        self, identifier: str
    ) -> PasswordEnrollment | None:
        """Read password state under an identity row lock by reset identifier.

        Args:
            identifier: The reset token identifier to match.

        Returns:
            Password state, including expired tokens, or None if no match remains.
        """
        return await self._get(self.table.c.reset_token_identifier == identifier)

    async def _get(
        self, condition: sqlalchemy.ColumnElement[bool]
    ) -> PasswordEnrollment | None:
        self._require_transaction()
        result = await self.connection.execute(
            sqlalchemy.select(
                self.table.c.id,
                self.table.c.id.label("identity_id"),
                self.table.c.password_hash,
                self.table.c.reset_token_identifier,
                self.table.c.reset_token_verifier,
                self.table.c.reset_token_expires_at,
            )
            .where(condition)
            .with_for_update()
        )
        row = result.mappings().one_or_none()
        return PasswordEnrollment(**row) if row is not None else None

    async def update(self, enrollment: PasswordEnrollment) -> None:
        """Update a protected identity's password fields without committing.

        Args:
            enrollment: Password state read under transaction-long identity protection.

        Raises:
            TokenIdentifierCollision: If another identity holds the reset identifier.
            sqlalchemy.exc.IntegrityError: If another integrity constraint fails.
        """
        self._require_transaction()
        values = dataclasses.asdict(enrollment)
        del values["id"]
        del values["identity_id"]
        try:
            async with self.connection.begin_nested():
                await self.connection.execute(
                    sqlalchemy.update(self.table)
                    .where(self.table.c.id == enrollment.id)
                    .values(**values)
                )
        except sqlalchemy.exc.IntegrityError as error:
            if enrollment.reset_token_identifier is not None:
                existing_id = await self.connection.scalar(
                    sqlalchemy.select(self.table.c.id).where(
                        self.table.c.reset_token_identifier
                        == enrollment.reset_token_identifier,
                        self.table.c.id != enrollment.id,
                    )
                )
                if existing_id is not None:
                    raise TokenIdentifierCollision() from error
            raise
