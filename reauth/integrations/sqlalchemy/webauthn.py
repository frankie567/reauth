"""SQLAlchemy Core storage for WebAuthn credentials and pending ceremonies."""

import dataclasses
import datetime
import typing

import sqlalchemy
import sqlalchemy.exc
import sqlalchemy.ext.asyncio

from reauth.factors.webauthn import WebAuthnEnrollment, WebAuthnFactor
from reauth.factors.webauthn.state import WebAuthnState, WebAuthnStateService
from reauth.integrations.sqlalchemy.mixins import TransactionMixin
from reauth.tokens import TokenIdentifierCollision, TokenProvider

type ColumnType = (
    sqlalchemy.types.TypeEngine[typing.Any]
    | type[sqlalchemy.types.TypeEngine[typing.Any]]
)
_IDENTIFIER = sqlalchemy.String(255).with_variant(
    sqlalchemy.String(255, collation="utf8mb4_0900_bin"), "mysql"
)


def create_webauthn_enrollment_table(
    metadata: sqlalchemy.MetaData,
    *,
    name: str = "webauthn_enrollments",
    id_type: ColumnType = sqlalchemy.Integer,
    identity_id_type: ColumnType = sqlalchemy.Integer,
) -> sqlalchemy.Table:
    """Define application-owned credential storage, allowing several credentials per identity.

    Args:
        metadata: Application-owned metadata in which to register the table.
        name: The table name.
        id_type: The enrollment primary key's SQL type.
        identity_id_type: The application's identity ID type.

    Returns:
        The enrollment table registered in the supplied metadata.
    """
    return sqlalchemy.Table(
        name,
        metadata,
        sqlalchemy.Column("id", id_type, primary_key=True),
        sqlalchemy.Column("identity_id", identity_id_type, nullable=False, index=True),
        sqlalchemy.Column("rp_id", _IDENTIFIER, nullable=False),
        sqlalchemy.Column("factor_identifier", _IDENTIFIER, nullable=False),
        sqlalchemy.Column(
            "credential_id",
            sqlalchemy.LargeBinary().with_variant(sqlalchemy.VARBINARY(1023), "mysql"),
            nullable=False,
        ),
        sqlalchemy.Column("public_key", sqlalchemy.LargeBinary, nullable=False),
        sqlalchemy.Column("sign_count", sqlalchemy.BigInteger, nullable=False),
        sqlalchemy.UniqueConstraint("rp_id", "credential_id"),
    )


def create_webauthn_state_table(
    metadata: sqlalchemy.MetaData,
    *,
    name: str = "webauthn_states",
    id_type: ColumnType = sqlalchemy.Integer,
    identity_id_type: ColumnType = sqlalchemy.Integer,
    session_id_type: ColumnType = sqlalchemy.Integer,
) -> sqlalchemy.Table:
    """Define application-owned storage for short-lived registration and authentication attempts.

    Args:
        metadata: Application-owned metadata in which to register the table.
        name: The table name.
        id_type: The state primary key's SQL type.
        identity_id_type: The application's identity ID type.
        session_id_type: The application's session ID type.

    Returns:
        The state table registered in the supplied metadata.
    """
    return sqlalchemy.Table(
        name,
        metadata,
        sqlalchemy.Column("id", id_type, primary_key=True),
        sqlalchemy.Column("token_identifier", _IDENTIFIER, nullable=False, unique=True),
        sqlalchemy.Column("token_verifier", sqlalchemy.Text, nullable=False),
        sqlalchemy.Column("rp_id", _IDENTIFIER, nullable=False),
        sqlalchemy.Column("factor_identifier", _IDENTIFIER, nullable=False),
        sqlalchemy.Column("ceremony", sqlalchemy.String(32), nullable=False),
        sqlalchemy.Column("session_id", session_id_type, nullable=False),
        sqlalchemy.Column("identity_id", identity_id_type, nullable=True),
        sqlalchemy.Column("challenge", sqlalchemy.LargeBinary, nullable=False),
        sqlalchemy.Column("allowed_credential_ids", sqlalchemy.JSON, nullable=True),
        sqlalchemy.Column("expires_at", sqlalchemy.BigInteger, nullable=False),
    )


class SQLAlchemyWebAuthnFactor(TransactionMixin, WebAuthnFactor):
    """Implement get_user_handle to use this adapter inside an application-owned transaction."""

    def __init__(
        self,
        connection: sqlalchemy.ext.asyncio.AsyncConnection,
        table: sqlalchemy.Table,
        **kwargs: typing.Any,
    ) -> None:
        """Configure the factor and its enrollment storage.

        Args:
            connection: An application-owned connection with an active transaction.
            table: The WebAuthn enrollment table.
            **kwargs: Configuration forwarded to WebAuthnFactor.
        """
        self.connection = connection
        self._require_transaction()
        self.table = table
        super().__init__(**kwargs)

    def _select_enrollments(self) -> sqlalchemy.Select:
        self._require_transaction()
        return (
            sqlalchemy.select(
                *(self.table.c[f.name] for f in dataclasses.fields(WebAuthnEnrollment))
            )
            .where(
                self.table.c.rp_id == self.rp_id,
                self.table.c.factor_identifier == self.identifier,
            )
            .with_for_update()
        )

    async def get_enrollments(
        self, identity_id: typing.Any
    ) -> list[WebAuthnEnrollment]:
        """List the identity's credentials for this factor and relying party.

        Args:
            identity_id: The application identity that owns the enrollments.

        Returns:
            Matching enrollments ordered by record ID.
        """
        rows = await self.connection.execute(
            self._select_enrollments()
            .where(self.table.c.identity_id == identity_id)
            .order_by(self.table.c.id)
        )
        return [WebAuthnEnrollment(**row) for row in rows.mappings()]

    async def credential_exists(self, credential_id: bytes) -> bool:
        """Check for an existing registration across all factors for this relying party.

        Args:
            credential_id: The raw credential ID supplied by the authenticator.

        Returns:
            True if the credential is already registered with this relying party.
        """
        self._require_transaction()
        query = sqlalchemy.select(self.table.c.id).where(
            self.table.c.rp_id == self.rp_id,
            self.table.c.credential_id == credential_id,
        )
        return await self.connection.scalar(query) is not None

    async def get_by_credential_id(
        self, credential_id: bytes
    ) -> WebAuthnEnrollment | None:
        """Look up an enrollment for this factor and relying party.

        Args:
            credential_id: The raw credential ID supplied by the authenticator.

        Returns:
            The matching enrollment, or None if no credential matches.
        """
        rows = await self.connection.execute(
            self._select_enrollments().where(
                self.table.c.credential_id == credential_id
            )
        )
        row = rows.mappings().one_or_none()
        return WebAuthnEnrollment(**row) if row is not None else None

    async def insert(self, enrollment: WebAuthnEnrollment) -> typing.Any:
        """Store a verified credential.

        Args:
            enrollment: The verified enrollment to persist.

        Returns:
            The enrollment's record ID.

        Raises:
            sqlalchemy.exc.IntegrityError: If the insert violates a constraint, including
                when a concurrent registration inserts the same credential for the RP.
                The caller must roll back the transaction.
        """  # noqa: DOC502
        self._require_transaction()
        values = dataclasses.asdict(enrollment)
        if enrollment.id is None:
            del values["id"]
        result = await self.connection.execute(self.table.insert().values(**values))
        primary_key = result.inserted_primary_key
        assert primary_key is not None
        return primary_key[0]

    async def update(self, enrollment: WebAuthnEnrollment) -> None:
        """Persist the credential's signature counter.

        Args:
            enrollment: The existing enrollment with its updated signature counter.
        """
        self._require_transaction()
        await self.connection.execute(
            self.table.update()
            .where(self.table.c.id == enrollment.id)
            .values(sign_count=enrollment.sign_count)
        )

    async def delete(self, enrollment: WebAuthnEnrollment) -> None:
        """Revoke a credential.

        Args:
            enrollment: The credential enrollment to delete.
        """
        self._require_transaction()
        await self.connection.execute(
            self.table.delete().where(self.table.c.id == enrollment.id)
        )


class SQLAlchemyWebAuthnStateService(TransactionMixin, WebAuthnStateService):
    """Store ceremony state on the same caller-owned transaction as the factor."""

    def __init__(
        self,
        connection: sqlalchemy.ext.asyncio.AsyncConnection,
        table: sqlalchemy.Table,
        *,
        token_provider: TokenProvider,
        lifetime: datetime.timedelta = datetime.timedelta(minutes=5),
    ) -> None:
        """Configure storage for pending ceremonies.

        Args:
            connection: An application-owned connection with an active transaction.
            table: The WebAuthn ceremony state table.
            token_provider: Provider used to issue and verify opaque state tokens.
            lifetime: How long a ceremony may remain pending.
        """
        self.connection = connection
        self._require_transaction()
        self.table = table
        super().__init__(token_provider=token_provider, lifetime=lifetime)

    async def get_by_token_identifier(
        self, token_identifier: str
    ) -> WebAuthnState | None:
        """Look up pending ceremony state.

        Args:
            token_identifier: The identifier parsed from the opaque state token.

        Returns:
            The matching state, including expired state, or None if absent.
        """
        self._require_transaction()
        result = await self.connection.execute(
            sqlalchemy.select(
                *(self.table.c[f.name] for f in dataclasses.fields(WebAuthnState))
            )
            .where(self.table.c.token_identifier == token_identifier)
            .with_for_update()
        )
        row = result.mappings().one_or_none()
        return WebAuthnState(**row) if row is not None else None

    async def insert(self, state: WebAuthnState) -> typing.Any:
        """Store a pending ceremony.

        Args:
            state: The ceremony state to persist.

        Returns:
            The state's record ID.

        Raises:
            TokenIdentifierCollision: If the token identifier is already in use.
            IntegrityError: If the insert fails another integrity constraint.
        """
        self._require_transaction()
        values = dataclasses.asdict(state)
        if state.id is None:
            del values["id"]
        try:
            async with self.connection.begin_nested():
                result = await self.connection.execute(
                    self.table.insert().values(**values)
                )
                primary_key = result.inserted_primary_key
                assert primary_key is not None
                return primary_key[0]
        except sqlalchemy.exc.IntegrityError as error:
            existing = await self.connection.scalar(
                sqlalchemy.select(self.table.c.id)
                .where(self.table.c.token_identifier == state.token_identifier)
                .with_for_update()
            )
            if existing is not None:
                raise TokenIdentifierCollision() from error
            raise

    async def delete(self, state: WebAuthnState) -> None:
        """Delete a pending ceremony.

        Args:
            state: The ceremony state to delete.
        """
        self._require_transaction()
        await self.connection.execute(
            self.table.delete().where(self.table.c.id == state.id)
        )
