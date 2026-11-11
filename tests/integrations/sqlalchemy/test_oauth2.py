import dataclasses
import typing
import uuid
from collections.abc import AsyncGenerator

import pytest
import sqlalchemy
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from reauth.factors.oauth2.base import OAuth2Enrollment
from reauth.integrations.sqlalchemy import (
    MissingTransactionException,
    SQLAlchemyAppleOAuth2Factor,
    SQLAlchemyGitHubOAuth2Factor,
    SQLAlchemyGoogleOAuth2Factor,
    SQLAlchemyOAuth2Mixin,
    SQLAlchemyOAuth2StateService,
    SQLAlchemyOIDCFactor,
    SQLAlchemyPrivateKeyJWTOIDCFactor,
    create_oauth2_enrollment_table,
    create_oauth2_state_table,
)
from reauth.tokens import ChecksummedTokenProvider, HMACTokenVerifier


def make_state_service(
    connection: AsyncConnection, table: sqlalchemy.Table
) -> SQLAlchemyOAuth2StateService:
    return SQLAlchemyOAuth2StateService(
        connection,
        table.metadata.tables["oauth2_states"],
        token_provider=ChecksummedTokenProvider(
            prefix="reauth_oauth2_",
            verifier=HMACTokenVerifier(current_key_id="test", keys={"test": b"t" * 32}),
        ),
    )


def make_factor(
    connection: AsyncConnection, table: sqlalchemy.Table, identifier: str = "google"
) -> SQLAlchemyGoogleOAuth2Factor:
    return SQLAlchemyGoogleOAuth2Factor(
        connection,
        table,
        identifier=identifier,
        client_id="client",
        client_secret="secret",
        state_service=make_state_service(connection, table),
    )


@pytest.fixture
async def table(
    sqlalchemy_integration_engine: AsyncEngine,
) -> AsyncGenerator[sqlalchemy.Table]:
    metadata = sqlalchemy.MetaData()
    table = create_oauth2_enrollment_table(metadata)
    create_oauth2_state_table(metadata)
    async with sqlalchemy_integration_engine.begin() as connection:
        await connection.run_sync(metadata.create_all)
    try:
        yield table
    finally:
        async with sqlalchemy_integration_engine.begin() as connection:
            await connection.run_sync(metadata.drop_all)


@pytest.fixture
def enrollment() -> OAuth2Enrollment:
    return OAuth2Enrollment(
        id=None,
        identity_id=1,
        provider="google",
        account_id="account",
        access_token="provider-access-token",
        expires_at=None,
        refresh_token="provider-refresh-token",
        refresh_token_expires_at=None,
        scope=["openid", "email"],
        id_token="provider-id-token",
    )


@pytest.mark.anyio
class TestSQLAlchemyOAuth2:
    @pytest.mark.parametrize(
        "factor_class,kwargs",
        [
            (SQLAlchemyGoogleOAuth2Factor, {"client_secret": "secret"}),
            (SQLAlchemyGitHubOAuth2Factor, {"client_secret": "secret"}),
            (
                SQLAlchemyAppleOAuth2Factor,
                {"team_id": "team", "key_id": "key", "key_value": "private-key"},
            ),
            (
                SQLAlchemyOIDCFactor,
                {
                    "identifier": "oidc",
                    "client_secret": "secret",
                    "discovery_endpoint": "https://example.com/discovery",
                },
            ),
            (
                SQLAlchemyPrivateKeyJWTOIDCFactor,
                {
                    "identifier": "oidc-jwt",
                    "signer": object(),
                    "discovery_endpoint": "https://example.com/discovery",
                },
            ),
        ],
    )
    async def test_composes_with_provider_factors(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        table: sqlalchemy.Table,
        factor_class: typing.Any,
        kwargs: dict[str, typing.Any],
    ) -> None:
        async with sqlalchemy_integration_engine.begin() as connection:
            factor = factor_class(
                connection,
                table,
                client_id="client",
                state_service=make_state_service(connection, table),
                step=2,
                advance_by=2,
                **kwargs,
            )
            assert isinstance(factor, SQLAlchemyOAuth2Mixin)
            assert factor.step == 2
            assert factor.advance_by == 2
            assert await factor.get_enrollment(1) is None

    async def test_requires_transaction(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        table: sqlalchemy.Table,
        enrollment: OAuth2Enrollment,
    ) -> None:
        async with sqlalchemy_integration_engine.connect() as connection:
            with pytest.raises(MissingTransactionException):
                make_factor(connection, table)
            async with connection.begin():
                factor = make_factor(connection, table)
            for operation in (
                lambda: factor.get_enrollment(1),
                lambda: factor.get_enrollment_by_provider_and_account(
                    "google", "account"
                ),
                lambda: factor.insert(enrollment),
                lambda: factor.update(enrollment),
            ):
                with pytest.raises(MissingTransactionException):
                    await operation()
                assert not connection.in_transaction()

    @pytest.mark.parametrize("record_id", [None, 42])
    @pytest.mark.parametrize("commit", [False, True])
    async def test_insert_transaction_ownership(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        table: sqlalchemy.Table,
        enrollment: OAuth2Enrollment,
        record_id: int | None,
        commit: bool,
    ) -> None:
        enrollment.id = record_id
        async with sqlalchemy_integration_engine.connect() as connection:
            transaction = await connection.begin()
            enrollment_id = await make_factor(connection, table).insert(enrollment)
            assert enrollment.id == record_id
            assert enrollment_id is not None
            if record_id is not None:
                assert enrollment_id == record_id
            async with sqlalchemy_integration_engine.connect() as observer:
                assert (
                    await observer.execute(sqlalchemy.select(table))
                ).first() is None
            if commit:
                await transaction.commit()
            else:
                await transaction.rollback()
        async with sqlalchemy_integration_engine.connect() as connection:
            row = (
                (await connection.execute(sqlalchemy.select(table)))
                .mappings()
                .one_or_none()
            )
            if commit:
                assert row is not None
                assert dict(row) == {
                    **dataclasses.asdict(enrollment),
                    "id": enrollment_id,
                }
            else:
                assert row is None

    async def test_lookup_scopes_identity_provider_and_account(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        table: sqlalchemy.Table,
        enrollment: OAuth2Enrollment,
    ) -> None:
        google = dataclasses.replace(enrollment, id=42)
        github = dataclasses.replace(enrollment, id=43, provider="github")
        other = dataclasses.replace(
            enrollment, id=44, identity_id=2, account_id="other"
        )
        work = dataclasses.replace(enrollment, id=45, provider="google-work")
        async with sqlalchemy_integration_engine.begin() as connection:
            await connection.execute(
                sqlalchemy.insert(table),
                [dataclasses.asdict(item) for item in (google, github, other, work)],
            )
        async with sqlalchemy_integration_engine.begin() as connection:
            factor = make_factor(connection, table)
            assert await factor.get_enrollment(1) == google
            assert await factor.get_enrollment(2) == other
            assert await factor.get_enrollment(999) is None
            assert (
                await make_factor(
                    connection, table, identifier="github"
                ).get_enrollment(1)
                == github
            )
            assert (
                await make_factor(
                    connection, table, identifier="google-work"
                ).get_enrollment(1)
                == work
            )
            assert (
                await factor.get_enrollment_by_provider_and_account("google", "account")
                == google
            )
            assert (
                await factor.get_enrollment_by_provider_and_account("github", "account")
                == github
            )
            assert (
                await factor.get_enrollment_by_provider_and_account(
                    "unknown", "account"
                )
                is None
            )
            assert (
                await factor.get_enrollment_by_provider_and_account("google", "unknown")
                is None
            )

    @pytest.mark.parametrize(
        "field,first_value,second_value",
        [
            ("account_id", "User123", "user123"),
            ("account_id", "subject", "subject "),
            ("provider", "Provider", "provider"),
            ("provider", "provider", "provider "),
        ],
    )
    async def test_identifier_comparisons_are_exact(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        table: sqlalchemy.Table,
        enrollment: OAuth2Enrollment,
        field: str,
        first_value: str,
        second_value: str,
    ) -> None:
        first = dataclasses.replace(enrollment, id=42, **{field: first_value})
        second = dataclasses.replace(
            enrollment,
            id=43,
            identity_id=2 if field == "account_id" else 1,
            **{field: second_value},
        )
        async with sqlalchemy_integration_engine.begin() as connection:
            await connection.execute(
                sqlalchemy.insert(table).values(**dataclasses.asdict(first))
            )
        async with sqlalchemy_integration_engine.begin() as connection:
            factor = make_factor(connection, table)
            assert (
                await factor.get_enrollment_by_provider_and_account(
                    second.provider, second.account_id
                )
                is None
            )
            if field == "provider":
                assert (
                    await make_factor(
                        connection, table, identifier=second.provider
                    ).get_enrollment(1)
                    is None
                )
            await connection.execute(
                sqlalchemy.insert(table).values(**dataclasses.asdict(second))
            )
            for expected in (first, second):
                assert (
                    await factor.get_enrollment_by_provider_and_account(
                        expected.provider, expected.account_id
                    )
                    == expected
                )
                assert (
                    await make_factor(
                        connection, table, identifier=expected.provider
                    ).get_enrollment(expected.identity_id)
                    == expected
                )

    @pytest.mark.parametrize(
        "identity_id,account_id", [(1, "different"), (2, "account"), (1, "account")]
    )
    async def test_enrollment_uniqueness(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        table: sqlalchemy.Table,
        enrollment: OAuth2Enrollment,
        identity_id: int,
        account_id: str,
    ) -> None:
        async with sqlalchemy_integration_engine.begin() as connection:
            await connection.execute(
                sqlalchemy.insert(table).values(
                    **dataclasses.asdict(dataclasses.replace(enrollment, id=42))
                )
            )
        with pytest.raises(IntegrityError):
            async with sqlalchemy_integration_engine.begin() as connection:
                await make_factor(connection, table).insert(
                    dataclasses.replace(
                        enrollment, identity_id=identity_id, account_id=account_id
                    )
                )

    @pytest.mark.parametrize("commit", [False, True])
    async def test_update_transaction_ownership(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        table: sqlalchemy.Table,
        enrollment: OAuth2Enrollment,
        commit: bool,
    ) -> None:
        enrollment.id = 42
        async with sqlalchemy_integration_engine.begin() as connection:
            await connection.execute(
                sqlalchemy.insert(table).values(**dataclasses.asdict(enrollment))
            )
        async with sqlalchemy_integration_engine.connect() as connection:
            transaction = await connection.begin()
            factor = make_factor(connection, table)
            stored = await factor.get_enrollment(1)
            assert stored is not None
            stored.access_token = "replacement-access"
            stored.refresh_token = None
            stored.scope = ["openid"]
            await factor.update(stored)
            if commit:
                await transaction.commit()
            else:
                await transaction.rollback()
        async with sqlalchemy_integration_engine.begin() as connection:
            current = await make_factor(connection, table).get_enrollment(1)
            assert current == (stored if commit else enrollment)

    async def test_custom_ids_and_application_columns(
        self, sqlalchemy_integration_engine: AsyncEngine, enrollment: OAuth2Enrollment
    ) -> None:
        metadata = sqlalchemy.MetaData()
        table = create_oauth2_enrollment_table(
            metadata, identity_id_type=sqlalchemy.Uuid()
        )
        create_oauth2_state_table(metadata)
        table.append_column(
            sqlalchemy.Column(
                "id", sqlalchemy.Uuid(), primary_key=True, default=uuid.uuid4
            ),
            replace_existing=True,
        )
        table.append_column(
            sqlalchemy.Column(
                "application_state", sqlalchemy.String(32), server_default="pending"
            )
        )
        async with sqlalchemy_integration_engine.begin() as connection:
            await connection.run_sync(metadata.create_all)
        try:
            async with sqlalchemy_integration_engine.begin() as connection:
                factor = make_factor(connection, table)
                enrollment.identity_id = uuid.uuid4()
                enrollment.id = await factor.insert(enrollment)
                assert isinstance(enrollment.id, uuid.UUID)
                assert await factor.get_enrollment(enrollment.identity_id) == enrollment
                enrollment.access_token = "updated"
                await factor.update(enrollment)
                row = (
                    (await connection.execute(sqlalchemy.select(table)))
                    .mappings()
                    .one()
                )
                assert row["application_state"] == "pending"
                assert row["access_token"] == "updated"
        finally:
            async with sqlalchemy_integration_engine.begin() as connection:
                await connection.run_sync(metadata.drop_all)

    @pytest.mark.parametrize("lookup", ["identity", "account"])
    async def test_lookup_locks_until_commit(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        table: sqlalchemy.Table,
        enrollment: OAuth2Enrollment,
        lookup: str,
    ) -> None:
        if sqlalchemy_integration_engine.dialect.name == "sqlite":
            pytest.skip("SQLite does not support SELECT FOR UPDATE")
        enrollment.id = 42
        async with sqlalchemy_integration_engine.begin() as connection:
            await connection.execute(
                sqlalchemy.insert(table).values(**dataclasses.asdict(enrollment))
            )
        async with (
            sqlalchemy_integration_engine.connect() as first,
            sqlalchemy_integration_engine.begin() as second,
        ):
            transaction = await first.begin()
            factor = make_factor(first, table)
            if lookup == "identity":
                stored = await factor.get_enrollment(1)
            else:
                stored = await factor.get_enrollment_by_provider_and_account(
                    "google", "account"
                )
            assert stored is not None
            if second.dialect.name == "postgresql":
                await second.execute(
                    sqlalchemy.text("SET LOCAL lock_timeout = '100ms'")
                )
            else:
                await second.execute(
                    sqlalchemy.text("SET SESSION innodb_lock_wait_timeout = 1")
                )
            async with second.begin_nested() as savepoint:
                with pytest.raises(DBAPIError) as error:
                    await make_factor(second, table).get_enrollment(1)
                assert error.value.orig is not None
                if second.dialect.name == "postgresql":
                    assert getattr(error.value.orig, "sqlstate", None) == "55P03"
                else:
                    assert error.value.orig.args[0] == 1205
                await savepoint.rollback()
            stored.access_token = "new-token"
            await factor.update(stored)
            await transaction.commit()
            current = await make_factor(second, table).get_enrollment(1)
            assert current is not None and current.access_token == "new-token"
