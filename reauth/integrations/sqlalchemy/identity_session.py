"""Identity session storage using SQLAlchemy Core."""

import dataclasses
import datetime
import typing

import sqlalchemy
import sqlalchemy.exc
import sqlalchemy.ext.asyncio

from reauth.amr import AuthenticationMethodReference
from reauth.identity_session import IdentitySession, IdentitySessionService
from reauth.integrations.sqlalchemy.exceptions import ReauthSQLAlchemyException
from reauth.integrations.sqlalchemy.mixins import TransactionMixin
from reauth.timestamp import get_current_timestamp
from reauth.tokens import TokenIdentifierCollision, TokenProvider


class InvalidSessionFamilyException(ReauthSQLAlchemyException):
    """Raised when insertion cannot protect an existing, unrevoked session family."""


def create_identity_session_table(
    metadata: sqlalchemy.MetaData,
    *,
    name: str = "identity_sessions",
    id_type: sqlalchemy.types.TypeEngine[typing.Any]
    | type[sqlalchemy.types.TypeEngine[typing.Any]] = sqlalchemy.Integer,
    identity_id_type: sqlalchemy.types.TypeEngine[typing.Any]
    | type[sqlalchemy.types.TypeEngine[typing.Any]] = sqlalchemy.Integer,
) -> sqlalchemy.Table:
    """
    Define an identity session table without creating it in the database.

    Args:
        metadata: Application-owned metadata, including any schema configuration.
        name: The table name.
        id_type: The session and lineage ID type. Supply a custom table for non-integer ID defaults.
        identity_id_type: The application's identity ID type.

    Returns:
        The table registered in the supplied metadata. Applications own migrations
        and cleanup. Retain family roots and replaced sessions through the family's
        absolute refresh deadline, and access-only sessions through their expiry.
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
        sqlalchemy.Column("identity_id", identity_id_type, nullable=False),
        sqlalchemy.Column("amr", sqlalchemy.JSON, nullable=False),
        sqlalchemy.Column("context", sqlalchemy.JSON, nullable=True),
        sqlalchemy.Column(
            "refresh_token_identifier",
            sqlalchemy.String(255),
            nullable=True,
            unique=True,
        ),
        sqlalchemy.Column("refresh_token_verifier", sqlalchemy.Text, nullable=True),
        sqlalchemy.Column(
            "refresh_token_expires_at", sqlalchemy.BigInteger, nullable=True
        ),
        sqlalchemy.Column("family_id", id_type, nullable=True, index=True),
        sqlalchemy.Column("replaced_by_id", id_type, nullable=True),
        sqlalchemy.Column("revoked_at", sqlalchemy.BigInteger, nullable=True),
    )


class SQLAlchemyIdentitySessionService(TransactionMixin, IdentitySessionService):
    """Store identity sessions within a caller-owned SQLAlchemy transaction."""

    def __init__(
        self,
        connection: sqlalchemy.ext.asyncio.AsyncConnection,
        table: sqlalchemy.Table,
        *,
        token_provider: TokenProvider,
        refresh_token_provider: TokenProvider,
        lifetime: datetime.timedelta = datetime.timedelta(hours=24),
        refresh_token_lifetime: datetime.timedelta = datetime.timedelta(days=30),
    ) -> None:
        """
        Initialize identity session storage.

        Args:
            connection: A connection with an active transaction. Do not use DBAPI
                autocommit. Keep the transaction open throughout each operation.
            table: A table containing the IdentitySession fields, a primary key on
                id, non-deferrable unique constraints on token_identifier and
                non-null refresh_token_identifier, and an index on family_id.
                Retain the initial session as the family lock anchor. All writers
                must acquire family protection before locking child sessions.
            token_provider: Access token generation and verification.
            refresh_token_provider: Refresh token generation and verification.
            lifetime: The access token lifetime.
            refresh_token_lifetime: The absolute lifetime of a refreshable family.

        Raises:
            MissingTransactionException: If the connection has no active transaction.
        """  # noqa: DOC502
        self.connection = connection
        self._require_transaction()
        self.table = table
        super().__init__(
            token_provider=token_provider,
            refresh_token_provider=refresh_token_provider,
            lifetime=lifetime,
            refresh_token_lifetime=refresh_token_lifetime,
        )

    async def insert(self, identity_session: IdentitySession) -> typing.Any:
        """
        Insert a session and initialize its family without committing.

        Returns:
            The inserted record ID.

        Raises:
            InvalidSessionFamilyException: If a child session's family is missing
                or revoked.
            TokenIdentifierCollision: If either identifier already exists.
            sqlalchemy.exc.IntegrityError: If another integrity constraint fails.
        """  # noqa: DOC502
        self._require_transaction()
        if (
            identity_session.family_id is not None
            and identity_session.family_id != identity_session.id
        ):
            root = await self._lock_family(identity_session.family_id)
            if root is None or root.revoked_at is not None:
                raise InvalidSessionFamilyException()
        try:
            async with self.connection.begin_nested():
                return await self._insert(identity_session)
        except sqlalchemy.exc.IntegrityError as error:
            await self._raise_identifier_collision(identity_session, error)
            raise

    async def get_by_token_identifier(
        self, token_identifier: str
    ) -> IdentitySession | None:
        """
        Read a session by access identifier with family protection acquired first.

        Returns:
            The stored session, including inactive rows, or None if the session or
            its family root is missing.
        """
        self._require_transaction()
        return await self._get_by_identifier("token_identifier", token_identifier)

    async def get_by_refresh_token_identifier(
        self, refresh_token_identifier: str
    ) -> IdentitySession | None:
        """
        Read a session by refresh identifier with family protection acquired first.

        Returns:
            The stored session, including inactive rows, or None if the session or
            its family root is missing.
        """
        self._require_transaction()
        return await self._get_by_identifier(
            "refresh_token_identifier", refresh_token_identifier
        )

    async def update_verifier(self, identity_session: IdentitySession) -> None:
        """Update only a previously protected session's access-token verifier."""
        self._require_transaction()
        await self.connection.execute(
            sqlalchemy.update(self.table)
            .where(self.table.c.id == identity_session.id)
            .values(token_verifier=identity_session.token_verifier)
        )

    async def replace(
        self, previous_session: IdentitySession, new_session: IdentitySession
    ) -> typing.Any | None:
        """
        Replace a currently eligible session atomically without committing.

        Returns:
            The inserted replacement ID, or None if the session is no longer eligible.

        Raises:
            TokenIdentifierCollision: If either replacement identifier already exists.
            sqlalchemy.exc.IntegrityError: If another integrity constraint fails.
        """  # noqa: DOC502
        self._require_transaction()
        root = await self._lock_family(previous_session.family_id)
        if root is None or root.revoked_at is not None:
            return None
        current = await self._read(
            self.table.c.id == previous_session.id,
            self.table.c.family_id == root.id,
        )
        if (
            current is None
            or current.family_id != root.id
            or current.refresh_token_identifier is None
            or current.refresh_token_verifier is None
            or current.refresh_token_identifier
            != previous_session.refresh_token_identifier
            or current.refresh_token_verifier != previous_session.refresh_token_verifier
            or current.refresh_token_expires_at is None
            or current.refresh_token_expires_at <= get_current_timestamp()
            or current.revoked_at is not None
            or current.replaced_by_id is not None
        ):
            return None
        replacement = dataclasses.replace(new_session, family_id=root.id)
        try:
            async with self.connection.begin_nested():
                session_id = await self._insert(replacement)
                await self.connection.execute(
                    sqlalchemy.update(self.table)
                    .where(self.table.c.id == current.id)
                    .values(replaced_by_id=session_id)
                )
                return session_id
        except sqlalchemy.exc.IntegrityError as error:
            await self._raise_identifier_collision(replacement, error)
            raise

    async def revoke_family(self, identity_session: IdentitySession) -> None:
        """Revoke unrevoked family members using the supplied timestamp, without committing."""
        self._require_transaction()
        root = await self._lock_family(identity_session.family_id)
        if root is None:
            return
        await self.connection.execute(
            sqlalchemy.update(self.table)
            .where(self.table.c.family_id == root.id, self.table.c.revoked_at.is_(None))
            .values(revoked_at=identity_session.revoked_at)
        )

    async def _insert(self, session: IdentitySession) -> typing.Any:
        values = dataclasses.asdict(session)
        if session.id is None:
            del values["id"]
        result = await self.connection.execute(
            sqlalchemy.insert(self.table).values(**values)
        )
        primary_key = result.inserted_primary_key
        assert primary_key is not None
        session_id = primary_key[0]
        if session.family_id is None:
            await self.connection.execute(
                sqlalchemy.update(self.table)
                .where(self.table.c.id == session_id)
                .values(family_id=session_id)
            )
        return session_id

    async def _get_by_identifier(
        self, column: str, identifier: str
    ) -> IdentitySession | None:
        # Discover the immutable family ID without taking a child lock first.
        family_id = await self.connection.scalar(
            sqlalchemy.select(self.table.c.family_id).where(
                self.table.c[column] == identifier
            )
        )
        root = await self._lock_family(family_id)
        if root is None:
            return None
        return await self._read(
            self.table.c[column] == identifier, self.table.c.family_id == root.id
        )

    async def _lock_family(self, family_id: typing.Any) -> IdentitySession | None:
        if family_id is None:
            return None
        root = await self._get_by_id(family_id)
        if root is None or root.family_id != root.id:
            return None
        return root

    async def _get_by_id(self, session_id: typing.Any) -> IdentitySession | None:
        return await self._read(self.table.c.id == session_id)

    async def _read(
        self, *conditions: sqlalchemy.ColumnElement[bool]
    ) -> IdentitySession | None:
        result = await self.connection.execute(
            sqlalchemy.select(
                *(
                    self.table.c[field.name]
                    for field in dataclasses.fields(IdentitySession)
                )
            )
            .where(*conditions)
            .with_for_update()
        )
        row = result.mappings().one_or_none()
        if row is None:
            return None
        session = IdentitySession(**row)
        session.amr = [AuthenticationMethodReference(value) for value in session.amr]
        return session

    async def _raise_identifier_collision(
        self, session: IdentitySession, error: sqlalchemy.exc.IntegrityError
    ) -> None:
        conditions = [self.table.c.token_identifier == session.token_identifier]
        if session.refresh_token_identifier is not None:
            conditions.append(
                self.table.c.refresh_token_identifier
                == session.refresh_token_identifier
            )
        existing_id = await self.connection.scalar(
            sqlalchemy.select(self.table.c.id)
            .where(sqlalchemy.or_(*conditions))
            .with_for_update()
            .limit(1)
        )
        if existing_id is not None:
            raise TokenIdentifierCollision() from error
