import dataclasses
import typing
import uuid
from collections.abc import AsyncGenerator

import anyio
import pytest
import sqlalchemy
import sqlalchemy.exc
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from reauth.authentication_session import AuthenticationSession
from reauth.factors.email_otp import EmailOTP, EmailOTPEnrollment, InvalidOTPException
from reauth.integrations.sqlalchemy import (
    AuthenticationSessionNotFoundException,
    MissingTransactionException,
    ReauthSQLAlchemyException,
    SQLAlchemyEmailOTPFactor,
    create_authentication_session_table,
    create_email_otp_table,
)
from reauth.timestamp import get_current_timestamp
from reauth.tokens import HMACTokenVerifier


class UserEmailOTPFactor(SQLAlchemyEmailOTPFactor):
    async def get_enrollment(
        self, identity_id: typing.Any
    ) -> EmailOTPEnrollment | None:
        self._require_transaction()
        users_table = self.table.metadata.tables["users"]
        result = await self.connection.execute(
            sqlalchemy.select(users_table.c.id, users_table.c.email)
            .where(users_table.c.id == identity_id)
            .with_for_update()
        )
        row = result.mappings().one_or_none()
        if row is None:
            return None
        return EmailOTPEnrollment(
            id=row["id"], identity_id=row["id"], email=row["email"]
        )


def make_factor(
    connection: AsyncConnection,
    tables: tuple[sqlalchemy.Table, sqlalchemy.Table, sqlalchemy.Table],
) -> SQLAlchemyEmailOTPFactor:
    otp_table, _, session_table = tables
    return UserEmailOTPFactor(
        connection,
        otp_table,
        authentication_session_table=session_table,
        verifier=HMACTokenVerifier(current_key_id="test", keys={"test": b"t" * 32}),
    )


@pytest.fixture
async def tables(
    sqlalchemy_integration_engine: AsyncEngine,
) -> AsyncGenerator[tuple[sqlalchemy.Table, sqlalchemy.Table, sqlalchemy.Table]]:
    metadata = sqlalchemy.MetaData()
    tables = (
        create_email_otp_table(metadata),
        sqlalchemy.Table(
            "users",
            metadata,
            sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
            sqlalchemy.Column("email", sqlalchemy.Text, nullable=False),
        ),
        create_authentication_session_table(metadata),
    )
    tables[1].append_column(
        sqlalchemy.Column(
            "application_state", sqlalchemy.String(32), server_default="pending"
        )
    )
    async with sqlalchemy_integration_engine.begin() as connection:
        await connection.run_sync(metadata.create_all)
        await connection.execute(
            sqlalchemy.insert(tables[2]).values(
                **dataclasses.asdict(
                    AuthenticationSession(
                        id=456,
                        token_identifier="test",
                        token_verifier="test",
                        expires_at=0,
                        identity_id=None,
                    )
                )
            )
        )
    try:
        yield tables
    finally:
        async with sqlalchemy_integration_engine.begin() as connection:
            await connection.run_sync(metadata.drop_all)


@pytest.fixture
def otp() -> EmailOTP:
    return EmailOTP(
        id=None,
        identity_id=None,
        email="reauth@example.com",
        code_verifier="opaque-verifier",
        expires_at=0,
        authentication_session_id=456,
    )


@pytest.mark.anyio
class TestSQLAlchemyEmailOTP:
    async def test_requires_transaction(
        self, sqlalchemy_integration_engine: AsyncEngine, tables, otp: EmailOTP
    ) -> None:
        async with sqlalchemy_integration_engine.connect() as connection:
            with pytest.raises(MissingTransactionException):
                make_factor(connection, tables)
            async with connection.begin():
                factor = make_factor(connection, tables)
            for operation in (
                lambda: factor.get_enrollment(123),
                lambda: factor.get_by_authentication_session_id(456),
                lambda: factor.insert(otp),
                lambda: factor.delete(otp),
                lambda: factor.delete_by_authentication_session_id(456),
            ):
                with pytest.raises(MissingTransactionException):
                    await operation()
                assert not connection.in_transaction()

    @pytest.mark.parametrize("record_id", [None, 42])
    @pytest.mark.parametrize("commit", [False, True])
    async def test_insert_transaction_ownership(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        tables,
        otp: EmailOTP,
        record_id: int | None,
        commit: bool,
    ) -> None:
        otp.id = record_id
        async with sqlalchemy_integration_engine.connect() as connection:
            transaction = await connection.begin()
            otp_id = await make_factor(connection, tables).insert(otp)
            assert otp.id == record_id
            assert otp_id is not None
            if record_id is not None:
                assert otp_id == record_id
            async with sqlalchemy_integration_engine.connect() as observer:
                assert (
                    await observer.execute(sqlalchemy.select(tables[0]))
                ).first() is None
            if commit:
                await transaction.commit()
            else:
                await transaction.rollback()
        async with sqlalchemy_integration_engine.connect() as connection:
            row = (
                (await connection.execute(sqlalchemy.select(tables[0])))
                .mappings()
                .one_or_none()
            )
            if commit:
                assert row is not None
                assert dict(row) == {**dataclasses.asdict(otp), "id": otp_id}
            else:
                assert row is None

    async def test_missing_parent(
        self, sqlalchemy_integration_engine: AsyncEngine, tables, otp: EmailOTP
    ) -> None:
        otp.authentication_session_id = 999
        async with sqlalchemy_integration_engine.begin() as connection:
            factor = make_factor(connection, tables)
            assert await factor.get_by_authentication_session_id(999) is None
            with pytest.raises(AuthenticationSessionNotFoundException) as error:
                await factor.create("reauth@example.com", 999)
            assert isinstance(error.value, ReauthSQLAlchemyException)
            with pytest.raises(AuthenticationSessionNotFoundException):
                await factor.insert(otp)
            assert (
                await connection.execute(sqlalchemy.select(tables[0]))
            ).first() is None

    async def test_lookup_includes_expired_and_scopes_session(
        self, sqlalchemy_integration_engine: AsyncEngine, tables, otp: EmailOTP
    ) -> None:
        otp.id = 42
        async with sqlalchemy_integration_engine.begin() as connection:
            await connection.execute(
                sqlalchemy.insert(tables[0]).values(**dataclasses.asdict(otp))
            )
        async with sqlalchemy_integration_engine.begin() as connection:
            factor = make_factor(connection, tables)
            assert await factor.get_by_authentication_session_id(456) == otp
            assert await factor.get_by_authentication_session_id(999) is None

    async def test_get_enrollment(
        self, sqlalchemy_integration_engine: AsyncEngine, tables
    ) -> None:
        enrollment = EmailOTPEnrollment(
            id=123, identity_id=123, email="reauth@example.com"
        )
        async with sqlalchemy_integration_engine.begin() as connection:
            await connection.execute(
                sqlalchemy.insert(tables[1]).values(id=123, email="reauth@example.com")
            )
            factor = make_factor(connection, tables)
            assert await factor.get_enrollment(123) == enrollment
            assert await factor.get_enrollment(999) is None

    async def test_unique_pending_otp(
        self, sqlalchemy_integration_engine: AsyncEngine, tables, otp: EmailOTP
    ) -> None:
        async with sqlalchemy_integration_engine.begin() as connection:
            await connection.execute(
                sqlalchemy.insert(tables[0]).values(
                    **dataclasses.asdict(dataclasses.replace(otp, id=42))
                )
            )
        async with sqlalchemy_integration_engine.connect() as connection:
            with pytest.raises(sqlalchemy.exc.IntegrityError):
                async with connection.begin():
                    await make_factor(connection, tables).insert(otp)

    @pytest.mark.parametrize("delete_all", [False, True])
    @pytest.mark.parametrize("commit", [False, True])
    async def test_delete_transaction_ownership(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        tables,
        otp: EmailOTP,
        delete_all: bool,
        commit: bool,
    ) -> None:
        otp.id = 42
        async with sqlalchemy_integration_engine.begin() as connection:
            await connection.execute(
                sqlalchemy.insert(tables[0]).values(**dataclasses.asdict(otp))
            )
        async with sqlalchemy_integration_engine.connect() as connection:
            transaction = await connection.begin()
            factor = make_factor(connection, tables)
            if delete_all:
                await factor.delete_by_authentication_session_id(456)
            else:
                stored = await factor.get_by_authentication_session_id(456)
                assert stored is not None
                await factor.delete(stored)
            if commit:
                await transaction.commit()
            else:
                await transaction.rollback()
        async with sqlalchemy_integration_engine.connect() as connection:
            row = (await connection.execute(sqlalchemy.select(tables[0]))).first()
            assert (row is None) == commit

    async def test_custom_ids_and_application_columns(
        self, sqlalchemy_integration_engine: AsyncEngine, tables, otp: EmailOTP
    ) -> None:
        metadata = tables[2].metadata
        custom = create_email_otp_table(
            metadata,
            name="custom_otps",
            id_type=sqlalchemy.Uuid(),
            identity_id_type=sqlalchemy.Uuid(),
        )
        custom.append_column(
            sqlalchemy.Column(
                "id", sqlalchemy.Uuid(), primary_key=True, default=uuid.uuid4
            ),
            replace_existing=True,
        )
        custom.append_column(
            sqlalchemy.Column(
                "application_state", sqlalchemy.String(32), server_default="pending"
            )
        )
        async with sqlalchemy_integration_engine.begin() as connection:
            await connection.run_sync(custom.create)
        try:
            async with sqlalchemy_integration_engine.begin() as connection:
                otp.identity_id = uuid.uuid4()
                factor = make_factor(connection, (custom, tables[1], tables[2]))
                otp.id = await factor.insert(otp)
                assert isinstance(otp.id, uuid.UUID)
                assert await factor.get_by_authentication_session_id(456) == otp
                row = (
                    (await connection.execute(sqlalchemy.select(custom)))
                    .mappings()
                    .one()
                )
                assert row["application_state"] == "pending"
        finally:
            async with sqlalchemy_integration_engine.begin() as connection:
                await connection.run_sync(custom.drop)

    @pytest.mark.parametrize("existing", [False, True])
    async def test_concurrent_creation_serializes_on_parent(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        tables,
        otp: EmailOTP,
        existing: bool,
    ) -> None:
        if sqlalchemy_integration_engine.dialect.name == "sqlite":
            pytest.skip("SQLite does not support SELECT FOR UPDATE")
        if existing:
            async with sqlalchemy_integration_engine.begin() as connection:
                await connection.execute(
                    sqlalchemy.insert(tables[0]).values(
                        **dataclasses.asdict(dataclasses.replace(otp, id=42))
                    )
                )
        attempted = anyio.Event()
        finished = anyio.Event()
        replacements: list[EmailOTP] = []

        async def create_again() -> None:
            async with sqlalchemy_integration_engine.begin() as connection:
                attempted.set()
                _, replacement = await make_factor(connection, tables).create(
                    "reauth@example.com", 456
                )
                replacements.append(replacement)
                finished.set()

        with anyio.fail_after(10):
            async with sqlalchemy_integration_engine.connect() as connection:
                transaction = await connection.begin()
                factor = make_factor(connection, tables)
                await factor.delete_by_authentication_session_id(456)
                async with anyio.create_task_group() as tasks:
                    tasks.start_soon(create_again)
                    await attempted.wait()
                    with anyio.move_on_after(0.1):
                        await finished.wait()
                    assert not finished.is_set()
                    await factor.insert(otp)
                    await transaction.commit()
                assert finished.is_set()
        async with sqlalchemy_integration_engine.begin() as connection:
            assert (
                await make_factor(connection, tables).get_by_authentication_session_id(
                    456
                )
                == replacements[0]
            )

    async def test_concurrent_consumption_rejects_replay(
        self, sqlalchemy_integration_engine: AsyncEngine, tables, otp: EmailOTP
    ) -> None:
        if sqlalchemy_integration_engine.dialect.name == "sqlite":
            pytest.skip("SQLite does not support SELECT FOR UPDATE")
        otp.id = 42
        otp.expires_at = get_current_timestamp() + 3600
        async with sqlalchemy_integration_engine.begin() as connection:
            otp.code_verifier = await make_factor(connection, tables).verifier.create(
                "ABC123"
            )
            await connection.execute(
                sqlalchemy.insert(tables[0]).values(**dataclasses.asdict(otp))
            )
        attempted = anyio.Event()
        finished = anyio.Event()

        async def consume_again() -> None:
            async with sqlalchemy_integration_engine.begin() as connection:
                attempted.set()
                with pytest.raises(InvalidOTPException):
                    await make_factor(connection, tables).consume("ABC123", 456)
                finished.set()

        with anyio.fail_after(10):
            async with sqlalchemy_integration_engine.connect() as connection:
                transaction = await connection.begin()
                await make_factor(connection, tables).consume("ABC123", 456)
                async with anyio.create_task_group() as tasks:
                    tasks.start_soon(consume_again)
                    await attempted.wait()
                    with anyio.move_on_after(0.1):
                        await finished.wait()
                    assert not finished.is_set()
                    await transaction.commit()
                assert finished.is_set()
