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
        rows = await self.connection.execute(
            self._select_enrollments()
            .where(self.table.c.identity_id == identity_id)
            .order_by(self.table.c.id)
        )
        return [WebAuthnEnrollment(**row) for row in rows.mappings()]

    async def get_by_credential_id(
        self, credential_id: bytes
    ) -> WebAuthnEnrollment | None:
        rows = await self.connection.execute(
            self._select_enrollments().where(
                self.table.c.credential_id == credential_id
            )
        )
        row = rows.mappings().one_or_none()
        return WebAuthnEnrollment(**row) if row is not None else None

    async def insert(self, enrollment: WebAuthnEnrollment) -> typing.Any:
        self._require_transaction()
        values = dataclasses.asdict(enrollment)
        if enrollment.id is None:
            del values["id"]
        result = await self.connection.execute(self.table.insert().values(**values))
        primary_key = result.inserted_primary_key
        assert primary_key is not None
        return primary_key[0]

    async def update(self, enrollment: WebAuthnEnrollment) -> None:
        self._require_transaction()
        await self.connection.execute(
            self.table.update()
            .where(self.table.c.id == enrollment.id)
            .values(sign_count=enrollment.sign_count)
        )

    async def delete(self, enrollment: WebAuthnEnrollment) -> None:
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
        self.connection = connection
        self._require_transaction()
        self.table = table
        super().__init__(token_provider=token_provider, lifetime=lifetime)

    async def get_by_token_identifier(
        self, token_identifier: str
    ) -> WebAuthnState | None:
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
        self._require_transaction()
        await self.connection.execute(
            self.table.delete().where(self.table.c.id == state.id)
        )
