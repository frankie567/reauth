import dataclasses
import typing
import uuid
from collections.abc import AsyncGenerator

import anyio
import pytest
import sqlalchemy
import sqlalchemy.exc
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from reauth.factors import EnrollmentCollision
from reauth.factors.backup_codes import (
    AlreadyUsedBackupCodeException,
    BackupCodesEnrollment,
)
from reauth.integrations.sqlalchemy import (
    MissingTransactionException,
    SQLAlchemyBackupCodesFactor,
    create_backup_codes_enrollment_table,
)
from reauth.tokens import HMACTokenVerifier


def make_enrollment(**kwargs: typing.Any) -> BackupCodesEnrollment:
    values: dict[str, typing.Any] = {
        "id": None,
        "identity_id": 1,
        "codes": ["opaque-verifier"],
        "used_codes": [],
        **kwargs,
    }
    return BackupCodesEnrollment(**values)


def make_factor(
    connection: AsyncConnection, table: sqlalchemy.Table
) -> SQLAlchemyBackupCodesFactor:
    return SQLAlchemyBackupCodesFactor(
        connection,
        table,
        verifier=HMACTokenVerifier(current_key_id="test", keys={"test": b"t" * 32}),
    )


@pytest.fixture
async def table(
    sqlalchemy_integration_engine: AsyncEngine,
) -> AsyncGenerator[sqlalchemy.Table]:
    table = create_backup_codes_enrollment_table(sqlalchemy.MetaData())
    async with sqlalchemy_integration_engine.begin() as connection:
        await connection.run_sync(table.metadata.create_all)
    try:
        yield table
    finally:
        async with sqlalchemy_integration_engine.begin() as connection:
            await connection.run_sync(table.metadata.drop_all)


@pytest.mark.anyio
class TestSQLAlchemyBackupCodes:
    async def test_requires_transaction(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        table: sqlalchemy.Table,
    ) -> None:
        enrollment = make_enrollment()
        async with sqlalchemy_integration_engine.connect() as connection:
            with pytest.raises(MissingTransactionException):
                make_factor(connection, table)
            async with connection.begin():
                factor = make_factor(connection, table)
            for operation in (
                lambda: factor.get_enrollment(1),
                lambda: factor.insert(enrollment),
                lambda: factor.update(enrollment),
                lambda: factor.delete(enrollment),
            ):
                with pytest.raises(MissingTransactionException):
                    await operation()
                assert not connection.in_transaction()

    @pytest.mark.parametrize("commit", [True, False])
    @pytest.mark.parametrize("record_id", [None, 42])
    async def test_insert_transaction_ownership(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        table: sqlalchemy.Table,
        commit: bool,
        record_id: int | None,
    ) -> None:
        enrollment = make_enrollment(id=record_id)
        async with sqlalchemy_integration_engine.connect() as connection:
            transaction = await connection.begin()
            enrollment_id = await make_factor(connection, table).insert(enrollment)
            assert enrollment_id is not None
            assert enrollment.id == record_id
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

    async def test_custom_ids_and_application_columns(
        self, sqlalchemy_integration_engine: AsyncEngine
    ) -> None:
        table = create_backup_codes_enrollment_table(
            sqlalchemy.MetaData(), identity_id_type=sqlalchemy.Uuid()
        )
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
        enrollment = make_enrollment(identity_id=uuid.uuid4())
        async with sqlalchemy_integration_engine.begin() as connection:
            await connection.run_sync(table.metadata.create_all)
        try:
            async with sqlalchemy_integration_engine.begin() as connection:
                factor = make_factor(connection, table)
                enrollment.id = await factor.insert(enrollment)
                assert isinstance(enrollment.id, uuid.UUID)
                assert (
                    await factor.get_by_identity_id(enrollment.identity_id)
                    == enrollment
                )
                enrollment.used_codes = enrollment.codes.copy()
                await factor.update(enrollment)
                row = (
                    (await connection.execute(sqlalchemy.select(table)))
                    .mappings()
                    .one()
                )
                assert row["used_codes"] == enrollment.codes
                assert row["application_state"] == "pending"
        finally:
            async with sqlalchemy_integration_engine.begin() as connection:
                await connection.run_sync(table.metadata.drop_all)

    async def test_lookup_and_update(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        table: sqlalchemy.Table,
    ) -> None:
        enrollment = make_enrollment(id=42)
        async with sqlalchemy_integration_engine.begin() as connection:
            await connection.execute(
                sqlalchemy.insert(table).values(**dataclasses.asdict(enrollment))
            )
        async with sqlalchemy_integration_engine.begin() as connection:
            factor = make_factor(connection, table)
            assert await factor.get_by_identity_id(999) is None
            assert await factor.get_by_identity_id(1) == enrollment
            assert await factor.get_enrollment(1) == enrollment
            enrollment.used_codes = enrollment.codes.copy()
            await factor.update(enrollment)
            assert await factor.get_enrollment(1) == enrollment
            row = (await connection.execute(sqlalchemy.select(table))).mappings().one()
            assert dict(row) == dataclasses.asdict(enrollment)

    @pytest.mark.parametrize("operation", ["update", "delete"])
    @pytest.mark.parametrize("commit", [True, False])
    async def test_mutation_transaction_ownership(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        table: sqlalchemy.Table,
        operation: str,
        commit: bool,
    ) -> None:
        enrollment = make_enrollment(id=42)
        async with sqlalchemy_integration_engine.begin() as connection:
            await connection.execute(
                sqlalchemy.insert(table).values(**dataclasses.asdict(enrollment))
            )
        async with sqlalchemy_integration_engine.connect() as connection:
            transaction = await connection.begin()
            factor = make_factor(connection, table)
            stored = await factor.get_by_identity_id(1)
            assert stored is not None
            stored.used_codes = stored.codes.copy()
            await getattr(factor, operation)(stored)
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
            if commit and operation == "delete":
                assert row is None
            else:
                assert row is not None
                expected_used_codes = (
                    enrollment.codes if commit and operation == "update" else []
                )
                assert row["used_codes"] == expected_used_codes

    async def test_identity_uniqueness(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        table: sqlalchemy.Table,
    ) -> None:
        enrollment = make_enrollment(id=42)
        async with sqlalchemy_integration_engine.begin() as connection:
            await connection.execute(
                sqlalchemy.insert(table).values(**dataclasses.asdict(enrollment))
            )
        async with sqlalchemy_integration_engine.begin() as connection:
            factor = make_factor(connection, table)
            with pytest.raises(EnrollmentCollision):
                await factor.insert(dataclasses.replace(enrollment, id=None))
            assert await factor.get_enrollment(1) == enrollment
            await factor.insert(dataclasses.replace(enrollment, id=None, identity_id=2))

    async def test_unrelated_integrity_error_preserves_transaction(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        table: sqlalchemy.Table,
    ) -> None:
        enrollment = make_enrollment(id=42)
        async with sqlalchemy_integration_engine.begin() as connection:
            await connection.execute(
                sqlalchemy.insert(table).values(**dataclasses.asdict(enrollment))
            )
        async with sqlalchemy_integration_engine.begin() as connection:
            factor = make_factor(connection, table)
            with pytest.raises(sqlalchemy.exc.IntegrityError):
                await factor.insert(dataclasses.replace(enrollment, identity_id=2))
            assert await factor.get_enrollment(1) == enrollment

    async def test_verify_rotates_verifier(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        table: sqlalchemy.Table,
    ) -> None:
        old_verifier = HMACTokenVerifier(current_key_id="old", keys={"old": b"o" * 32})
        enrollment = make_enrollment(id=42, codes=[await old_verifier.create("ABC123")])
        async with sqlalchemy_integration_engine.begin() as connection:
            await connection.execute(
                sqlalchemy.insert(table).values(**dataclasses.asdict(enrollment))
            )
        async with sqlalchemy_integration_engine.begin() as connection:
            factor = SQLAlchemyBackupCodesFactor(
                connection,
                table,
                verifier=HMACTokenVerifier(
                    current_key_id="new", keys={"old": b"o" * 32, "new": b"n" * 32}
                ),
            )
            verified = await factor.verify(1, "ABC123")
            assert verified.codes != enrollment.codes
            assert verified.used_codes == verified.codes
        async with sqlalchemy_integration_engine.begin() as connection:
            stored = await make_factor(connection, table).get_enrollment(1)
            assert stored == verified

    async def test_verify_persists_used_codes(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        table: sqlalchemy.Table,
    ) -> None:
        enrollment = make_enrollment(id=42)
        code = "ABC123"
        async with sqlalchemy_integration_engine.begin() as connection:
            enrollment.codes = [
                await make_factor(connection, table).verifier.create(code)
            ]
            await connection.execute(
                sqlalchemy.insert(table).values(**dataclasses.asdict(enrollment))
            )
        async with sqlalchemy_integration_engine.begin() as connection:
            verified = await make_factor(connection, table).verify(1, code)
            assert verified.used_codes == enrollment.codes
        async with sqlalchemy_integration_engine.begin() as connection:
            with pytest.raises(AlreadyUsedBackupCodeException):
                await make_factor(connection, table).verify(1, code)

    async def test_concurrent_verification_rejects_replay(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        table: sqlalchemy.Table,
    ) -> None:
        if sqlalchemy_integration_engine.dialect.name == "sqlite":
            pytest.skip("SQLite does not support SELECT FOR UPDATE")
        enrollment = make_enrollment(id=42)
        code = "ABC123"
        async with sqlalchemy_integration_engine.begin() as connection:
            enrollment.codes = [
                await make_factor(connection, table).verifier.create(code)
            ]
            await connection.execute(
                sqlalchemy.insert(table).values(**dataclasses.asdict(enrollment))
            )
        blocked = anyio.Event()
        committed = anyio.Event()

        async def verify_again() -> None:
            async with sqlalchemy_integration_engine.connect() as connection:
                transaction = await connection.begin()
                try:
                    if connection.dialect.name == "postgresql":
                        await connection.execute(
                            sqlalchemy.text("SET LOCAL lock_timeout = '100ms'")
                        )
                    else:
                        await connection.execute(
                            sqlalchemy.text("SET innodb_lock_wait_timeout = 1")
                        )
                    with pytest.raises(sqlalchemy.exc.DBAPIError) as error:
                        await make_factor(connection, table).verify(1, code)
                    assert error.value.orig is not None
                    if connection.dialect.name == "postgresql":
                        assert getattr(error.value.orig, "sqlstate", None) == "55P03"
                    else:
                        assert error.value.orig.args[0] == 1205
                finally:
                    await transaction.rollback()
                blocked.set()
                await committed.wait()
                async with connection.begin():
                    with pytest.raises(AlreadyUsedBackupCodeException):
                        await make_factor(connection, table).verify(1, code)

        with anyio.fail_after(10):
            async with sqlalchemy_integration_engine.connect() as connection:
                transaction = await connection.begin()
                await make_factor(connection, table).verify(1, code)
                async with anyio.create_task_group() as tasks:
                    tasks.start_soon(verify_again)
                    await blocked.wait()
                    await transaction.commit()
                    committed.set()
