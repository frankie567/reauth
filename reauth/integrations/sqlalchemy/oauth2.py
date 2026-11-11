"""Shared OAuth2 enrollment storage using SQLAlchemy Core."""

import dataclasses
import typing

import sqlalchemy
import sqlalchemy.ext.asyncio

from reauth.factors.oauth2.apple import AppleOAuth2Factor
from reauth.factors.oauth2.base import OAuth2Enrollment
from reauth.factors.oauth2.github import GitHubOAuth2Factor
from reauth.factors.oauth2.google import GoogleOAuth2Factor
from reauth.factors.oauth2.oidc import OIDCFactor, PrivateKeyJWTOIDCFactor, Signer
from reauth.factors.oauth2.state import OAuth2StateService
from reauth.integrations.sqlalchemy.mixins import TransactionMixin


def create_oauth2_enrollment_table(
    metadata: sqlalchemy.MetaData,
    *,
    name: str = "oauth2_enrollments",
    id_type: sqlalchemy.types.TypeEngine[typing.Any]
    | type[sqlalchemy.types.TypeEngine[typing.Any]] = sqlalchemy.Integer,
    identity_id_type: sqlalchemy.types.TypeEngine[typing.Any]
    | type[sqlalchemy.types.TypeEngine[typing.Any]] = sqlalchemy.Integer,
) -> sqlalchemy.Table:
    """
    Define a shared OAuth2 enrollment table without creating it in the database.

    Args:
        metadata: Application-owned metadata, including any schema configuration.
        name: The table name.
        id_type: The enrollment ID type. Supply a custom table for non-integer ID defaults.
        identity_id_type: The application's identity ID type.

    Returns:
        The table registered in the supplied metadata. Applications own migrations.
    """
    identifier_type = sqlalchemy.String(255).with_variant(
        sqlalchemy.String(255, collation="utf8mb4_0900_bin"), "mysql"
    )
    return sqlalchemy.Table(
        name,
        metadata,
        sqlalchemy.Column("id", id_type, primary_key=True),
        sqlalchemy.Column("identity_id", identity_id_type, nullable=False),
        sqlalchemy.Column("provider", identifier_type, nullable=False),
        sqlalchemy.Column("account_id", identifier_type, nullable=False),
        sqlalchemy.Column("access_token", sqlalchemy.Text, nullable=False),
        sqlalchemy.Column("expires_at", sqlalchemy.BigInteger, nullable=True),
        sqlalchemy.Column("refresh_token", sqlalchemy.Text, nullable=True),
        sqlalchemy.Column(
            "refresh_token_expires_at", sqlalchemy.BigInteger, nullable=True
        ),
        sqlalchemy.Column("scope", sqlalchemy.JSON, nullable=False),
        sqlalchemy.Column("id_token", sqlalchemy.Text, nullable=True),
        sqlalchemy.UniqueConstraint("identity_id", "provider"),
        sqlalchemy.UniqueConstraint("provider", "account_id"),
    )


class SQLAlchemyOAuth2Mixin(TransactionMixin):
    """
    Compose OAuth2 enrollment storage with an OAuth2 or OIDC factor class.

    Place this mixin before the factor class in the inheritance list. Providers can
    share a table; the configured factor identifier is the stored provider value.
    """

    identifier: str

    def __init__(
        self,
        connection: sqlalchemy.ext.asyncio.AsyncConnection,
        table: sqlalchemy.Table,
        **kwargs: typing.Any,
    ) -> None:
        """
        Initialize shared enrollment storage and the composed factor.

        Args:
            connection: A connection with an active transaction. Do not use DBAPI
                autocommit. Keep the transaction open throughout each operation.
            table: A table containing the OAuth2Enrollment fields, with a primary
                key on id and non-deferrable unique constraints on
                (identity_id, provider) and (provider, account_id). Provider and
                account_id must compare exactly, including case and trailing spaces.
                Provider credentials are stored as plaintext.
            **kwargs: Constructor arguments forwarded to the composed factor.

        Raises:
            MissingTransactionException: If the connection has no active transaction.
        """  # noqa: DOC502
        self.connection = connection
        self._require_transaction()
        self.table = table
        super().__init__(**kwargs)

    async def get_enrollment(self, identity_id: typing.Any) -> OAuth2Enrollment | None:
        """
        Read an identity's enrollment for this configured provider under a lock.

        Returns:
            The enrollment, or None if the identity has none for this provider.
        """
        self._require_transaction()
        result = await self.connection.execute(
            sqlalchemy.select(
                *(
                    self.table.c[field.name]
                    for field in dataclasses.fields(OAuth2Enrollment)
                )
            )
            .where(
                self.table.c.identity_id == identity_id,
                self.table.c.provider == self.identifier,
            )
            .with_for_update()
        )
        row = result.mappings().one_or_none()
        return OAuth2Enrollment(**row) if row is not None else None

    async def get_enrollment_by_provider_and_account(
        self, provider: str, account_id: str
    ) -> OAuth2Enrollment | None:
        """
        Read an enrollment matching both provider and account ID under a lock.

        Returns:
            The enrollment, or None if the external account is not enrolled.
        """
        self._require_transaction()
        result = await self.connection.execute(
            sqlalchemy.select(
                *(
                    self.table.c[field.name]
                    for field in dataclasses.fields(OAuth2Enrollment)
                )
            )
            .where(
                self.table.c.provider == provider, self.table.c.account_id == account_id
            )
            .with_for_update()
        )
        row = result.mappings().one_or_none()
        return OAuth2Enrollment(**row) if row is not None else None

    async def insert(self, enrollment: OAuth2Enrollment) -> typing.Any:
        """
        Insert an enrollment without committing the caller's transaction.

        Returns:
            The inserted record ID.

        """
        self._require_transaction()
        values = dataclasses.asdict(enrollment)
        if enrollment.id is None:
            del values["id"]
        result = await self.connection.execute(
            sqlalchemy.insert(self.table).values(**values)
        )
        primary_key = result.inserted_primary_key
        assert primary_key is not None
        return primary_key[0]

    async def update(self, enrollment: OAuth2Enrollment) -> None:
        """Update a previously protected enrollment without committing."""
        self._require_transaction()
        values = dataclasses.asdict(enrollment)
        del values["id"]
        await self.connection.execute(
            sqlalchemy.update(self.table)
            .where(self.table.c.id == enrollment.id)
            .values(**values)
        )


class SQLAlchemyGitHubOAuth2Factor(SQLAlchemyOAuth2Mixin, GitHubOAuth2Factor):
    """Store GitHubOAuth2Factor enrollments with an explicit provider constructor."""

    def __init__(
        self,
        connection: sqlalchemy.ext.asyncio.AsyncConnection,
        table: sqlalchemy.Table,
        *,
        identifier: str = "github",
        client_id: str,
        client_secret: str,
        state_service: OAuth2StateService,
        step: int = 0,
        advance_by: int = 1,
    ) -> None:
        super().__init__(
            connection,
            table,
            identifier=identifier,
            client_id=client_id,
            client_secret=client_secret,
            state_service=state_service,
            step=step,
            advance_by=advance_by,
        )


class SQLAlchemyGoogleOAuth2Factor(SQLAlchemyOAuth2Mixin, GoogleOAuth2Factor):
    """Store GoogleOAuth2Factor enrollments with an explicit provider constructor."""

    def __init__(
        self,
        connection: sqlalchemy.ext.asyncio.AsyncConnection,
        table: sqlalchemy.Table,
        *,
        identifier: str = "google",
        client_id: str,
        client_secret: str,
        state_service: OAuth2StateService,
        step: int = 0,
        advance_by: int = 1,
    ) -> None:
        super().__init__(
            connection,
            table,
            identifier=identifier,
            client_id=client_id,
            client_secret=client_secret,
            state_service=state_service,
            step=step,
            advance_by=advance_by,
        )


class SQLAlchemyAppleOAuth2Factor(SQLAlchemyOAuth2Mixin, AppleOAuth2Factor):
    """Store AppleOAuth2Factor enrollments with an explicit provider constructor."""

    def __init__(
        self,
        connection: sqlalchemy.ext.asyncio.AsyncConnection,
        table: sqlalchemy.Table,
        *,
        identifier: str = "apple",
        client_id: str,
        team_id: str,
        key_id: str,
        key_value: str,
        state_service: OAuth2StateService,
        step: int = 0,
        advance_by: int = 1,
    ) -> None:
        super().__init__(
            connection,
            table,
            identifier=identifier,
            client_id=client_id,
            team_id=team_id,
            key_id=key_id,
            key_value=key_value,
            state_service=state_service,
            step=step,
            advance_by=advance_by,
        )


class SQLAlchemyOIDCFactor(SQLAlchemyOAuth2Mixin, OIDCFactor):
    """Store OIDCFactor enrollments with an explicit provider constructor."""

    def __init__(
        self,
        connection: sqlalchemy.ext.asyncio.AsyncConnection,
        table: sqlalchemy.Table,
        *,
        identifier: str,
        client_id: str,
        client_secret: str,
        discovery_endpoint: str,
        state_service: OAuth2StateService,
        step: int = 0,
        advance_by: int = 1,
    ) -> None:
        super().__init__(
            connection,
            table,
            identifier=identifier,
            client_id=client_id,
            client_secret=client_secret,
            discovery_endpoint=discovery_endpoint,
            state_service=state_service,
            step=step,
            advance_by=advance_by,
        )


class SQLAlchemyPrivateKeyJWTOIDCFactor(SQLAlchemyOAuth2Mixin, PrivateKeyJWTOIDCFactor):
    """Store PrivateKeyJWTOIDCFactor enrollments with an explicit provider constructor."""

    def __init__(
        self,
        connection: sqlalchemy.ext.asyncio.AsyncConnection,
        table: sqlalchemy.Table,
        *,
        identifier: str,
        client_id: str,
        signer: Signer,
        discovery_endpoint: str,
        state_service: OAuth2StateService,
        assertion_lifetime: int = 60,
        step: int = 0,
        advance_by: int = 1,
    ) -> None:
        super().__init__(
            connection,
            table,
            identifier=identifier,
            client_id=client_id,
            signer=signer,
            discovery_endpoint=discovery_endpoint,
            state_service=state_service,
            assertion_lifetime=assertion_lifetime,
            step=step,
            advance_by=advance_by,
        )
