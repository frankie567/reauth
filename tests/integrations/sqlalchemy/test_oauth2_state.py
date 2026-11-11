import dataclasses
import uuid
from collections.abc import AsyncGenerator

import pytest
import sqlalchemy
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from reauth.factors.oauth2.state import InvalidStateException, OAuth2State
from reauth.integrations.sqlalchemy import (
    MissingTransactionException,
    SQLAlchemyOAuth2StateService,
    create_oauth2_state_table,
)
from reauth.timestamp import get_current_timestamp
from reauth.tokens import (
    ChecksummedTokenProvider,
    HMACTokenVerifier,
    TokenIdentifierCollision,
)


def make_service(
    connection: AsyncConnection, table: sqlalchemy.Table
) -> SQLAlchemyOAuth2StateService:
    return SQLAlchemyOAuth2StateService(
        connection,
        table,
        token_provider=ChecksummedTokenProvider(
            prefix="reauth_oauth2_",
            verifier=HMACTokenVerifier(current_key_id="test", keys={"test": b"t" * 32}),
        ),
    )


@pytest.fixture
async def table(
    sqlalchemy_integration_engine: AsyncEngine,
) -> AsyncGenerator[sqlalchemy.Table]:
    metadata = sqlalchemy.MetaData()
    table = create_oauth2_state_table(metadata)
    async with sqlalchemy_integration_engine.begin() as connection:
        await connection.run_sync(metadata.create_all)
    try:
        yield table
    finally:
        async with sqlalchemy_integration_engine.begin() as connection:
            await connection.run_sync(metadata.drop_all)


@pytest.fixture
def state() -> OAuth2State:
    return OAuth2State(
        id=None,
        token_identifier="identifier",
        token_verifier="opaque-verifier",
        provider="google",
        code_verifier="pkce-verifier",
        nonce="nonce",
        redirect_uri="https://example.com/callback",
        identity_id=None,
        scope=["openid", "email"],
        expires_at=0,
        context={"return_to": "/dashboard"},
    )


@pytest.mark.anyio
class TestSQLAlchemyOAuth2State:
    async def test_requires_transaction(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        table: sqlalchemy.Table,
        state: OAuth2State,
    ) -> None:
        async with sqlalchemy_integration_engine.connect() as connection:
            with pytest.raises(MissingTransactionException):
                make_service(connection, table)
            async with connection.begin():
                service = make_service(connection, table)
            for operation in (
                lambda: service.get_by_token_identifier("identifier"),
                lambda: service.insert(state),
                lambda: service.delete(state),
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
        state: OAuth2State,
        record_id: int | None,
        commit: bool,
    ) -> None:
        state.id = record_id
        async with sqlalchemy_integration_engine.connect() as connection:
            transaction = await connection.begin()
            state_id = await make_service(connection, table).insert(state)
            assert state.id == record_id
            assert state_id is not None
            if record_id is not None:
                assert state_id == record_id
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
                assert dict(row) == {**dataclasses.asdict(state), "id": state_id}
            else:
                assert row is None

    async def test_custom_ids_and_application_columns(
        self, sqlalchemy_integration_engine: AsyncEngine, state: OAuth2State
    ) -> None:
        metadata = sqlalchemy.MetaData()
        table = create_oauth2_state_table(metadata, identity_id_type=sqlalchemy.Uuid())
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
                service = make_service(connection, table)
                state.identity_id = uuid.uuid4()
                state.id = await service.insert(state)
                assert isinstance(state.id, uuid.UUID)
                assert (
                    await service.get_by_token_identifier(state.token_identifier)
                    == state
                )
                row = (
                    (await connection.execute(sqlalchemy.select(table)))
                    .mappings()
                    .one()
                )
                assert row["application_state"] == "pending"
        finally:
            async with sqlalchemy_integration_engine.begin() as connection:
                await connection.run_sync(metadata.drop_all)

    async def test_lookup_includes_expired_state(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        table: sqlalchemy.Table,
        state: OAuth2State,
    ) -> None:
        state.id = 42
        async with sqlalchemy_integration_engine.begin() as connection:
            await connection.execute(
                sqlalchemy.insert(table).values(**dataclasses.asdict(state))
            )
        async with sqlalchemy_integration_engine.begin() as connection:
            service = make_service(connection, table)
            assert (
                await service.get_by_token_identifier(state.token_identifier) == state
            )
            assert await service.get_by_token_identifier("unknown") is None

    async def test_collision_preserves_transaction(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        table: sqlalchemy.Table,
        state: OAuth2State,
    ) -> None:
        async with sqlalchemy_integration_engine.begin() as connection:
            await connection.execute(
                sqlalchemy.insert(table).values(
                    **dataclasses.asdict(dataclasses.replace(state, id=42))
                )
            )
        async with sqlalchemy_integration_engine.begin() as connection:
            service = make_service(connection, table)
            with pytest.raises(TokenIdentifierCollision):
                await service.insert(state)
            assert await service.get_by_token_identifier("identifier") is not None
            await service.insert(dataclasses.replace(state, token_identifier="another"))

    async def test_unrelated_integrity_error_preserves_transaction(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        table: sqlalchemy.Table,
        state: OAuth2State,
    ) -> None:
        state.id = 42
        async with sqlalchemy_integration_engine.begin() as connection:
            await connection.execute(
                sqlalchemy.insert(table).values(**dataclasses.asdict(state))
            )
        async with sqlalchemy_integration_engine.begin() as connection:
            service = make_service(connection, table)
            with pytest.raises(IntegrityError):
                await service.insert(
                    dataclasses.replace(state, token_identifier="another")
                )
            assert await service.get_by_token_identifier("identifier") == state

    @pytest.mark.parametrize("commit", [False, True])
    async def test_delete_transaction_ownership(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        table: sqlalchemy.Table,
        state: OAuth2State,
        commit: bool,
    ) -> None:
        state.id = 42
        async with sqlalchemy_integration_engine.begin() as connection:
            await connection.execute(
                sqlalchemy.insert(table).values(**dataclasses.asdict(state))
            )
        async with sqlalchemy_integration_engine.connect() as connection:
            transaction = await connection.begin()
            service = make_service(connection, table)
            stored = await service.get_by_token_identifier("identifier")
            assert stored is not None
            await service.delete(stored)
            if commit:
                await transaction.commit()
            else:
                await transaction.rollback()
        async with sqlalchemy_integration_engine.connect() as connection:
            row = (await connection.execute(sqlalchemy.select(table))).first()
            assert (row is None) == commit

    async def test_consumption_locks_and_rejects_replay(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        table: sqlalchemy.Table,
        state: OAuth2State,
    ) -> None:
        if sqlalchemy_integration_engine.dialect.name == "sqlite":
            pytest.skip("SQLite does not support SELECT FOR UPDATE")
        async with sqlalchemy_integration_engine.begin() as connection:
            generated = await make_service(connection, table).token_provider.generate()
            state = dataclasses.replace(
                state,
                id=42,
                token_identifier=generated.identifier,
                token_verifier=generated.verifier,
                expires_at=get_current_timestamp() + 3600,
            )
            await connection.execute(
                sqlalchemy.insert(table).values(**dataclasses.asdict(state))
            )
        async with (
            sqlalchemy_integration_engine.connect() as first,
            sqlalchemy_integration_engine.begin() as second,
        ):
            transaction = await first.begin()
            assert await make_service(first, table).consume(generated.token) == state
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
                    await make_service(second, table).consume(generated.token)
                assert error.value.orig is not None
                if second.dialect.name == "postgresql":
                    assert getattr(error.value.orig, "sqlstate", None) == "55P03"
                else:
                    assert error.value.orig.args[0] == 1205
                await savepoint.rollback()
            await transaction.commit()
            with pytest.raises(InvalidStateException):
                await make_service(second, table).consume(generated.token)
