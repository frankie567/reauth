"""Authentication session storage using SQLAlchemy Core."""

import dataclasses
import datetime
import typing

import sqlalchemy
import sqlalchemy.exc
import sqlalchemy.ext.asyncio

from reauth.amr import AuthenticationMethodReference
from reauth.authentication_session import (
    AuthenticationSession,
    AuthenticationSessionService,
)
from reauth.factors import FactorBase
from reauth.integrations.sqlalchemy.exceptions import MissingTransactionException
from reauth.tokens import TokenIdentifierCollision, TokenProvider


def create_authentication_session_table(
    metadata: sqlalchemy.MetaData,
    *,
    name: str = "authentication_sessions",
    id_type: sqlalchemy.types.TypeEngine[typing.Any]
    | type[sqlalchemy.types.TypeEngine[typing.Any]] = sqlalchemy.Integer,
    identity_id_type: sqlalchemy.types.TypeEngine[typing.Any]
    | type[sqlalchemy.types.TypeEngine[typing.Any]] = sqlalchemy.Integer,
) -> sqlalchemy.Table:
    """
    Define an authentication session table without creating it in the database.

    Args:
        metadata: Application-owned metadata, including any schema configuration.
        name: The table name.
        id_type: The session ID type. Supply a custom table for non-integer ID defaults.
        identity_id_type: The application's identity ID type.

    Returns:
        The table registered in the supplied metadata. Applications own migrations.
    """
    return sqlalchemy.Table(
        name,
        metadata,
        sqlalchemy.Column("id", id_type, primary_key=True),
        sqlalchemy.Column(
            "token_identifier", sqlalchemy.String(255), nullable=False, unique=True
        ),
        sqlalchemy.Column("token_verifier", sqlalchemy.Text, nullable=False),
        sqlalchemy.Column("expires_at", sqlalchemy.BigInteger, nullable=False),
        sqlalchemy.Column("identity_id", identity_id_type, nullable=True),
        sqlalchemy.Column("step", sqlalchemy.Integer, nullable=False),
        sqlalchemy.Column("amr", sqlalchemy.JSON, nullable=False),
        sqlalchemy.Column("used_factors", sqlalchemy.JSON, nullable=False),
        sqlalchemy.Column("context", sqlalchemy.JSON, nullable=True),
    )


class SQLAlchemyAuthenticationSessionService(AuthenticationSessionService):
    """Store authentication sessions within a caller-owned SQLAlchemy transaction."""

    def __init__(
        self,
        connection: sqlalchemy.ext.asyncio.AsyncConnection,
        table: sqlalchemy.Table,
        *,
        token_provider: TokenProvider,
        factors: set[FactorBase[typing.Any]],
        lifetime: datetime.timedelta = datetime.timedelta(minutes=15),
    ) -> None:
        """
        Initialize authentication session storage.

        Args:
            connection: A connection with an active transaction. Do not use
                DBAPI autocommit. Keep the transaction open throughout each operation.
            table: A table containing the AuthenticationSession fields, with a primary
                key on id and a non-deferrable unique constraint on token_identifier.
            token_provider: Access token generation and verification.
            factors: The available authentication factors.
            lifetime: The authentication session lifetime.

        Raises:
            MissingTransactionException: If the connection has no active transaction.
        """
        if not connection.in_transaction():
            raise MissingTransactionException()
        self.connection = connection
        self.table = table
        super().__init__(
            token_provider=token_provider, factors=factors, lifetime=lifetime
        )

    async def insert(self, authentication_session: AuthenticationSession) -> typing.Any:
        """
        Insert a session without committing the caller's transaction.

        Args:
            authentication_session: The session to persist.

        Returns:
            The inserted record ID.

        Raises:
            TokenIdentifierCollision: If the token identifier already exists.
            MissingTransactionException: If the connection has no active transaction.
            sqlalchemy.exc.IntegrityError: If another integrity constraint fails.
        """  # noqa: DOC502
        self._require_transaction()
        values = dataclasses.asdict(authentication_session)
        if authentication_session.id is None:
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
                sqlalchemy.select(self.table.c.id).where(
                    self.table.c.token_identifier
                    == authentication_session.token_identifier
                )
            )
            if existing_id is not None:
                raise TokenIdentifierCollision() from error
            raise

    async def get_by_token_identifier(
        self, token_identifier: str
    ) -> AuthenticationSession | None:
        """
        Retrieve a session under a row lock retained until the transaction ends.

        Args:
            token_identifier: The token identifier to match.

        Returns:
            The session, including expired sessions, or None if it does not exist.

        Raises:
            MissingTransactionException: If the connection has no active transaction.
        """  # noqa: DOC502
        self._require_transaction()
        result = await self.connection.execute(
            sqlalchemy.select(
                *(
                    self.table.c[field.name]
                    for field in dataclasses.fields(AuthenticationSession)
                )
            )
            .where(self.table.c.token_identifier == token_identifier)
            .with_for_update()
        )
        row = result.mappings().one_or_none()
        if row is None:
            return None
        session = AuthenticationSession(**row)
        session.amr = [AuthenticationMethodReference(value) for value in session.amr]
        return session

    async def update(self, authentication_session: AuthenticationSession) -> None:
        """Update a previously protected session without committing."""
        self._require_transaction()
        values = dataclasses.asdict(authentication_session)
        del values["id"]
        await self.connection.execute(
            sqlalchemy.update(self.table)
            .where(self.table.c.id == authentication_session.id)
            .values(**values)
        )

    async def delete(self, authentication_session: AuthenticationSession) -> None:
        """Delete a previously protected session without committing."""
        self._require_transaction()
        await self.connection.execute(
            sqlalchemy.delete(self.table).where(
                self.table.c.id == authentication_session.id
            )
        )

    def _require_transaction(self) -> None:
        if not self.connection.in_transaction():
            raise MissingTransactionException()
