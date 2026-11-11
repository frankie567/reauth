import dataclasses
import uuid
from collections.abc import AsyncGenerator

import pytest
import sqlalchemy
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from reauth.amr import AuthenticationMethodReference
from reauth.authentication_session import AuthenticationSession
from reauth.exceptions import ReauthException
from reauth.integrations.sqlalchemy import (
    MissingTransactionException,
    ReauthSQLAlchemyException,
    SQLAlchemyAuthenticationSessionService,
    create_authentication_session_table,
)
from reauth.tokens import (
    ChecksummedTokenProvider,
    HMACTokenVerifier,
    TokenIdentifierCollision,
)


def make_service(
    connection: AsyncConnection, table: sqlalchemy.Table
) -> SQLAlchemyAuthenticationSessionService:
    return SQLAlchemyAuthenticationSessionService(
        connection,
        table,
        token_provider=ChecksummedTokenProvider(
            prefix="reauth_as_",
            verifier=HMACTokenVerifier(current_key_id="test", keys={"test": b"t" * 32}),
        ),
        factors=set(),
    )


@pytest.fixture
async def table(
    sqlalchemy_integration_engine: AsyncEngine,
) -> AsyncGenerator[sqlalchemy.Table]:
    metadata = sqlalchemy.MetaData()
    table = create_authentication_session_table(
        metadata, name="adapter_authentication_sessions"
    )
    async with sqlalchemy_integration_engine.begin() as connection:
        await connection.run_sync(metadata.create_all)
    try:
        yield table
    finally:
        async with sqlalchemy_integration_engine.begin() as connection:
            await connection.run_sync(metadata.drop_all)


@pytest.fixture
def session() -> AuthenticationSession:
    return AuthenticationSession(
        id=None,
        token_identifier="test-identifier",
        token_verifier="opaque-verifier",
        expires_at=0,
        identity_id=None,
        amr=[AuthenticationMethodReference.PWD],
        used_factors=["password"],
        context={"return_to": "/dashboard"},
    )


@pytest.mark.anyio
class TestSQLAlchemyAuthenticationSession:
    async def test_custom_table_with_uuid_ids_and_additional_columns(
        self, sqlalchemy_integration_engine: AsyncEngine, session: AuthenticationSession
    ) -> None:
        metadata = sqlalchemy.MetaData()
        table = create_authentication_session_table(
            metadata,
            name="custom_authentication_sessions",
            identity_id_type=sqlalchemy.Uuid(),
        )
        table.append_column(
            sqlalchemy.Column(
                "id", sqlalchemy.Uuid(), primary_key=True, default=uuid.uuid4
            ),
            replace_existing=True,
        )
        table.append_column(
            sqlalchemy.Column(
                "application_state", sqlalchemy.String(255), server_default="pending"
            )
        )
        async with sqlalchemy_integration_engine.begin() as connection:
            await connection.run_sync(metadata.create_all)
            service = make_service(connection, table)
            session.identity_id = uuid.uuid4()
            session.id = await service.insert(session)
            assert isinstance(session.id, uuid.UUID)
            stored = await service.get_by_token_identifier(session.token_identifier)
            assert stored == session
            assert stored is not None
            stored.step = 1
            await service.update(stored)
            row = (await connection.execute(sqlalchemy.select(table))).mappings().one()
            assert row["step"] == 1
            assert row["application_state"] == "pending"
            await connection.run_sync(metadata.drop_all)

    async def test_requires_transaction(
        self, sqlalchemy_integration_engine: AsyncEngine, table: sqlalchemy.Table
    ) -> None:
        async with sqlalchemy_integration_engine.connect() as connection:
            with pytest.raises(MissingTransactionException) as error:
                make_service(connection, table)
            assert isinstance(error.value, ReauthSQLAlchemyException)
            assert isinstance(error.value, ReauthException)

    async def test_rejects_operations_after_transaction_ends(
        self, sqlalchemy_integration_engine: AsyncEngine, table: sqlalchemy.Table
    ) -> None:
        async with sqlalchemy_integration_engine.connect() as connection:
            async with connection.begin():
                service = make_service(connection, table)
            with pytest.raises(MissingTransactionException):
                await service.start()
            assert not connection.in_transaction()

    @pytest.mark.parametrize("commit", [True, False])
    async def test_insert_transaction_ownership(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        table: sqlalchemy.Table,
        session: AuthenticationSession,
        commit: bool,
    ) -> None:
        async with sqlalchemy_integration_engine.connect() as connection:
            transaction = await connection.begin()
            session_id = await make_service(connection, table).insert(session)
            assert session_id is not None
            assert session.id is None
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
                assert dict(row) == {**dataclasses.asdict(session), "id": session_id}
            else:
                assert row is None

    async def test_collision_leaves_transaction_usable(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        table: sqlalchemy.Table,
        session: AuthenticationSession,
    ) -> None:
        async with sqlalchemy_integration_engine.begin() as connection:
            await connection.execute(
                sqlalchemy.insert(table).values(
                    **{
                        key: value
                        for key, value in dataclasses.asdict(session).items()
                        if key != "id"
                    }
                )
            )
            service = make_service(connection, table)
            with pytest.raises(TokenIdentifierCollision):
                await service.insert(session)
            session.token_identifier = "another-identifier"
            await service.insert(session)
            assert (
                await connection.scalar(
                    sqlalchemy.select(sqlalchemy.func.count()).select_from(table)
                )
                == 2
            )

    async def test_other_integrity_errors_are_not_collisions(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        table: sqlalchemy.Table,
        session: AuthenticationSession,
    ) -> None:
        async with sqlalchemy_integration_engine.begin() as connection:
            session.id = 1
            await connection.execute(
                sqlalchemy.insert(table).values(**dataclasses.asdict(session))
            )
            session.token_identifier = "another-identifier"
            with pytest.raises(IntegrityError):
                await make_service(connection, table).insert(session)
            assert (
                await connection.scalar(
                    sqlalchemy.select(sqlalchemy.func.count()).select_from(table)
                )
                == 1
            )

    async def test_lookup_returns_expired_session_and_enum_values(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        table: sqlalchemy.Table,
        session: AuthenticationSession,
    ) -> None:
        async with sqlalchemy_integration_engine.begin() as connection:
            session.id = 1
            await connection.execute(
                sqlalchemy.insert(table).values(**dataclasses.asdict(session))
            )
            service = make_service(connection, table)
            stored = await service.get_by_token_identifier(session.token_identifier)
            assert stored == session
            assert stored is not None
            assert stored.amr[0] is AuthenticationMethodReference.PWD
            assert await service.get_by_token_identifier("missing") is None

    @pytest.mark.parametrize("operation", ["update", "delete"])
    @pytest.mark.parametrize("commit", [True, False])
    async def test_mutation_transaction_ownership(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        table: sqlalchemy.Table,
        session: AuthenticationSession,
        operation: str,
        commit: bool,
    ) -> None:
        session.id = 1
        async with sqlalchemy_integration_engine.begin() as connection:
            await connection.execute(
                sqlalchemy.insert(table).values(**dataclasses.asdict(session))
            )
        async with sqlalchemy_integration_engine.connect() as connection:
            transaction = await connection.begin()
            service = make_service(connection, table)
            protected = await service.get_by_token_identifier(session.token_identifier)
            assert protected is not None
            if operation == "update":
                protected.identity_id = 42
                protected.step = 2
                await service.update(protected)
            else:
                await service.delete(protected)
            assert transaction.is_active
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
            if not commit:
                assert row is not None and dict(row) == dataclasses.asdict(session)
            elif operation == "delete":
                assert row is None
            else:
                assert row is not None and row["identity_id"] == 42 and row["step"] == 2

    async def test_lookup_locks_until_commit(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        table: sqlalchemy.Table,
        session: AuthenticationSession,
    ) -> None:
        if sqlalchemy_integration_engine.dialect.name == "sqlite":
            pytest.skip("SQLite does not support SELECT FOR UPDATE row locks")
        session.id = 1
        async with sqlalchemy_integration_engine.begin() as connection:
            await connection.execute(
                sqlalchemy.insert(table).values(**dataclasses.asdict(session))
            )
        async with (
            sqlalchemy_integration_engine.connect() as first,
            sqlalchemy_integration_engine.begin() as second,
        ):
            transaction = await first.begin()
            service = make_service(first, table)
            protected = await service.get_by_token_identifier(session.token_identifier)
            assert protected is not None
            if sqlalchemy_integration_engine.dialect.name == "postgresql":
                await second.execute(
                    sqlalchemy.text("SET LOCAL lock_timeout = '100ms'")
                )
            else:
                await second.execute(
                    sqlalchemy.text("SET SESSION innodb_lock_wait_timeout = 1")
                )
            async with second.begin_nested() as savepoint:
                with pytest.raises(DBAPIError) as error:
                    await make_service(second, table).get_by_token_identifier(
                        session.token_identifier
                    )
                if sqlalchemy_integration_engine.dialect.name == "postgresql":
                    assert getattr(error.value.orig, "sqlstate", None) == "55P03"
                else:
                    assert error.value.orig is not None
                    assert error.value.orig.args[0] == 1205
                await savepoint.rollback()
            protected.step = 1
            await service.update(protected)
            await transaction.commit()
            current = await make_service(second, table).get_by_token_identifier(
                session.token_identifier
            )
            assert current is not None and current.step == 1
