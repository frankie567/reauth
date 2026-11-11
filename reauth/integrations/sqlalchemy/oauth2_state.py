"""OAuth2 state storage using SQLAlchemy Core."""

import dataclasses
import datetime
import typing

import sqlalchemy
import sqlalchemy.exc
import sqlalchemy.ext.asyncio

from reauth.factors.oauth2.state import OAuth2State, OAuth2StateService
from reauth.integrations.sqlalchemy.mixins import TransactionMixin
from reauth.tokens import TokenIdentifierCollision, TokenProvider


def create_oauth2_state_table(
    metadata: sqlalchemy.MetaData,
    *,
    name: str = "oauth2_states",
    id_type: sqlalchemy.types.TypeEngine[typing.Any]
    | type[sqlalchemy.types.TypeEngine[typing.Any]] = sqlalchemy.Integer,
    identity_id_type: sqlalchemy.types.TypeEngine[typing.Any]
    | type[sqlalchemy.types.TypeEngine[typing.Any]] = sqlalchemy.Integer,
) -> sqlalchemy.Table:
    """
    Define an OAuth2 state table without creating it in the database.

    Args:
        metadata: Application-owned metadata, including any schema configuration.
        name: The table name.
        id_type: The state ID type. Supply a custom table for non-integer ID defaults.
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
        sqlalchemy.Column("provider", sqlalchemy.String(255), nullable=False),
        sqlalchemy.Column("code_verifier", sqlalchemy.Text, nullable=True),
        sqlalchemy.Column("nonce", sqlalchemy.Text, nullable=True),
        sqlalchemy.Column("redirect_uri", sqlalchemy.Text, nullable=False),
        sqlalchemy.Column("identity_id", identity_id_type, nullable=True),
        sqlalchemy.Column("scope", sqlalchemy.JSON, nullable=True),
        sqlalchemy.Column("expires_at", sqlalchemy.BigInteger, nullable=False),
        sqlalchemy.Column("context", sqlalchemy.JSON, nullable=True),
    )


class SQLAlchemyOAuth2StateService(TransactionMixin, OAuth2StateService):
    """Store OAuth2 state within a caller-owned SQLAlchemy transaction."""

    def __init__(
        self,
        connection: sqlalchemy.ext.asyncio.AsyncConnection,
        table: sqlalchemy.Table,
        *,
        token_provider: TokenProvider,
        lifetime: datetime.timedelta = datetime.timedelta(minutes=10),
    ) -> None:
        """
        Initialize OAuth2 state storage.

        Args:
            connection: A connection with an active transaction. Do not use DBAPI
                autocommit. Keep the transaction open throughout each operation.
            table: A table containing the OAuth2State fields, with a primary key on
                id and a non-deferrable unique constraint on token_identifier.
            token_provider: State token generation and verification.
            lifetime: The state lifetime.

        Raises:
            MissingTransactionException: If the connection has no active transaction.
        """  # noqa: DOC502
        self.connection = connection
        self._require_transaction()
        self.table = table
        super().__init__(token_provider=token_provider, lifetime=lifetime)

    async def get_by_token_identifier(
        self, token_identifier: str
    ) -> OAuth2State | None:
        """
        Read state, including expired records, under a transaction-long lock.

        Returns:
            The state, or None if it does not exist.
        """
        self._require_transaction()
        result = await self.connection.execute(
            sqlalchemy.select(
                *(self.table.c[field.name] for field in dataclasses.fields(OAuth2State))
            )
            .where(self.table.c.token_identifier == token_identifier)
            .with_for_update()
        )
        row = result.mappings().one_or_none()
        return OAuth2State(**row) if row is not None else None

    async def insert(self, oauth2_state: OAuth2State) -> typing.Any:
        """
        Insert state without committing the caller's transaction.

        Returns:
            The inserted record ID.

        Raises:
            TokenIdentifierCollision: If the state identifier already exists.
            sqlalchemy.exc.IntegrityError: If another integrity constraint fails.
        """
        self._require_transaction()
        values = dataclasses.asdict(oauth2_state)
        if oauth2_state.id is None:
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
                .where(self.table.c.token_identifier == oauth2_state.token_identifier)
                .with_for_update()
            )
            if existing_id is not None:
                raise TokenIdentifierCollision() from error
            raise

    async def delete(self, oauth2_state: OAuth2State) -> None:
        """Delete previously protected state without committing."""
        self._require_transaction()
        await self.connection.execute(
            sqlalchemy.delete(self.table).where(self.table.c.id == oauth2_state.id)
        )
