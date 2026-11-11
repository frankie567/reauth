import dataclasses
import types
import typing
import uuid
from collections.abc import AsyncGenerator

import anyio
import pytest
import sqlalchemy
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from reauth.factors.totp import InvalidTOTPCodeException, TOTPEnrollment
from reauth.integrations.sqlalchemy import (
    EnrollmentAlreadyExistsException,
    MissingTransactionException,
    SQLAlchemyTOTPFactor,
    create_totp_enrollment_table,
)


def make_enrollment(**kwargs: typing.Any) -> TOTPEnrollment:
    values: dict[str, typing.Any] = {
        "id": None,
        "identity_id": 1,
        "enabled": False,
        "secret": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        "algorithm": "sha1",
        "code_length": 6,
        **kwargs,
    }
    return TOTPEnrollment(**values, time_step=30)


def make_factor(
    connection: AsyncConnection, table: sqlalchemy.Table
) -> SQLAlchemyTOTPFactor:
    return SQLAlchemyTOTPFactor(connection, table, drift_tolerance=0)


def make_code(enrollment: TOTPEnrollment) -> str:
    return enrollment._impl.generate(1234567890).decode("ascii")


@pytest.fixture
async def table(
    sqlalchemy_integration_engine: AsyncEngine,
) -> AsyncGenerator[sqlalchemy.Table]:
    table = create_totp_enrollment_table(sqlalchemy.MetaData())
    async with sqlalchemy_integration_engine.begin() as connection:
        await connection.run_sync(table.metadata.create_all)
    try:
        yield table
    finally:
        async with sqlalchemy_integration_engine.begin() as connection:
            await connection.run_sync(table.metadata.drop_all)


@pytest.mark.anyio
class TestSQLAlchemyTOTP:
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
                lambda: factor.get_by_identity_id(1),
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
        table = create_totp_enrollment_table(
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
                enrollment.enabled = True
                await factor.update(enrollment)
                row = (
                    (await connection.execute(sqlalchemy.select(table)))
                    .mappings()
                    .one()
                )
                assert row["enabled"]
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
            assert await factor.get_enrollment(1) is None
            enrollment.enabled = True
            enrollment.last_verified_time_step = 2**32
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
            stored.enabled = True
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
                assert row["enabled"] == (commit and operation == "update")

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
        async with sqlalchemy_integration_engine.connect() as connection:
            with pytest.raises(EnrollmentAlreadyExistsException):
                async with connection.begin():
                    await make_factor(connection, table).insert(
                        dataclasses.replace(enrollment, id=None)
                    )

    async def test_enable_persists_replay_protection(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        table: sqlalchemy.Table,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(
            "reauth.factors.totp.time", types.SimpleNamespace(time=lambda: 1234567890)
        )
        enrollment = make_enrollment(id=42)
        code = make_code(enrollment)
        async with sqlalchemy_integration_engine.begin() as connection:
            await connection.execute(
                sqlalchemy.insert(table).values(**dataclasses.asdict(enrollment))
            )
        async with sqlalchemy_integration_engine.begin() as connection:
            enabled = await make_factor(connection, table).enable(1, code)
            assert enabled.enabled
        async with sqlalchemy_integration_engine.begin() as connection:
            with pytest.raises(InvalidTOTPCodeException):
                await make_factor(connection, table).verify(1, code)

    async def test_concurrent_verification_rejects_replay(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        table: sqlalchemy.Table,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        if sqlalchemy_integration_engine.dialect.name == "sqlite":
            pytest.skip("SQLite does not support SELECT FOR UPDATE")
        monkeypatch.setattr(
            "reauth.factors.totp.time", types.SimpleNamespace(time=lambda: 1234567890)
        )
        enrollment = make_enrollment(id=42, enabled=True)
        code = make_code(enrollment)
        async with sqlalchemy_integration_engine.begin() as connection:
            await connection.execute(
                sqlalchemy.insert(table).values(**dataclasses.asdict(enrollment))
            )
        attempted = anyio.Event()
        finished = anyio.Event()

        async def verify_again() -> None:
            async with sqlalchemy_integration_engine.begin() as connection:
                factor = make_factor(connection, table)
                attempted.set()
                with pytest.raises(InvalidTOTPCodeException):
                    await factor.verify(1, code)
                finished.set()

        with anyio.fail_after(10):
            async with sqlalchemy_integration_engine.connect() as connection:
                transaction = await connection.begin()
                await make_factor(connection, table).verify(1, code)
                async with anyio.create_task_group() as tasks:
                    tasks.start_soon(verify_again)
                    await attempted.wait()
                    with anyio.move_on_after(0.1):
                        await finished.wait()
                    assert not finished.is_set()
                    await transaction.commit()
                assert finished.is_set()
