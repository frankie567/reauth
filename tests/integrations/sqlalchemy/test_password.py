import dataclasses
from collections.abc import AsyncGenerator

import anyio
import pytest
import sqlalchemy
import sqlalchemy.exc
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from reauth.factors.password import (
    InvalidPasswordResetTokenException,
    PasswordEnrollment,
)
from reauth.integrations.sqlalchemy import (
    MissingTransactionException,
    SQLAlchemyPasswordFactor,
)
from reauth.tokens import (
    ChecksummedTokenProvider,
    HMACTokenVerifier,
    TokenIdentifierCollision,
)


def make_factor(
    connection: AsyncConnection, table: sqlalchemy.Table
) -> SQLAlchemyPasswordFactor:
    return SQLAlchemyPasswordFactor(
        connection,
        table,
        token_provider=ChecksummedTokenProvider(
            prefix="reset_",
            verifier=HMACTokenVerifier(
                current_key_id="test",
                keys={"test": b"x" * 32},
            ),
        ),
    )


@pytest.fixture
async def table(
    sqlalchemy_integration_engine: AsyncEngine,
) -> AsyncGenerator[sqlalchemy.Table]:
    table = sqlalchemy.Table(
        "password_users",
        sqlalchemy.MetaData(),
        sqlalchemy.Column("id", sqlalchemy.String(32), primary_key=True),
        sqlalchemy.Column("email", sqlalchemy.String(255), nullable=False),
        sqlalchemy.Column("password_hash", sqlalchemy.Text, nullable=True),
        sqlalchemy.Column(
            "reset_token_identifier", sqlalchemy.String(255), unique=True, nullable=True
        ),
        sqlalchemy.Column(
            "reset_token_verifier", sqlalchemy.String(255), nullable=True, unique=True
        ),
        sqlalchemy.Column(
            "reset_token_expires_at", sqlalchemy.BigInteger, nullable=True
        ),
    )
    async with sqlalchemy_integration_engine.begin() as connection:
        await connection.run_sync(table.metadata.create_all)
        await connection.execute(
            sqlalchemy.insert(table),
            [
                {
                    "id": "first",
                    "email": "reauth@example.com",
                    "password_hash": "stored",
                    "reset_token_identifier": "pending",
                    "reset_token_verifier": "verifier",
                    "reset_token_expires_at": 1,
                },
                {
                    "id": "second",
                    "email": "reauth@example.com",
                    "password_hash": None,
                    "reset_token_identifier": None,
                    "reset_token_verifier": None,
                    "reset_token_expires_at": None,
                },
            ],
        )
    try:
        yield table
    finally:
        async with sqlalchemy_integration_engine.begin() as connection:
            await connection.run_sync(table.metadata.drop_all)


@pytest.mark.anyio
class TestSQLAlchemyPassword:
    async def test_requires_transaction(self, sqlalchemy_integration_engine, table):
        async with sqlalchemy_integration_engine.connect() as connection:
            with pytest.raises(MissingTransactionException):
                make_factor(connection, table)
            async with connection.begin():
                factor = make_factor(connection, table)
            for operation in (
                lambda: factor.get_by_identity_id("first"),
                lambda: factor.get_by_reset_token_identifier("pending"),
                lambda: factor.update(PasswordEnrollment("first", "first", "new")),
            ):
                with pytest.raises(MissingTransactionException):
                    await operation()
                assert not connection.in_transaction()

    async def test_reads(self, sqlalchemy_integration_engine, table):
        async with sqlalchemy_integration_engine.begin() as connection:
            factor = make_factor(connection, table)
            enrollment = await factor.get_by_identity_id("first")
            assert enrollment is not None
            assert enrollment == PasswordEnrollment(
                "first", "first", "stored", "pending", "verifier", 1
            )
            assert await factor.get_by_reset_token_identifier("pending") == enrollment
            assert await factor.get_by_identity_id("second") == PasswordEnrollment(
                "second", "second", None
            )
            assert await factor.get_enrollment("second") is None
            assert await factor.get_by_identity_id("missing") is None
            assert await factor.get_by_reset_token_identifier("missing") is None

    @pytest.mark.parametrize("commit", [True, False])
    async def test_update_transaction_ownership(
        self, sqlalchemy_integration_engine, table, commit
    ):
        async with sqlalchemy_integration_engine.connect() as connection:
            transaction = await connection.begin()
            factor = make_factor(connection, table)
            enrollment = await factor.get_by_identity_id("first")
            assert enrollment is not None
            await factor.update(
                dataclasses.replace(
                    enrollment,
                    password_hash="new",
                    reset_token_identifier=None,
                    reset_token_verifier=None,
                    reset_token_expires_at=None,
                )
            )
            if commit:
                await transaction.commit()
            else:
                await transaction.rollback()
        async with sqlalchemy_integration_engine.connect() as connection:
            row = (
                (
                    await connection.execute(
                        sqlalchemy.select(table).where(table.c.id == "first")
                    )
                )
                .mappings()
                .one()
            )
            assert row["password_hash"] == ("new" if commit else "stored")
            assert row["reset_token_identifier"] == (None if commit else "pending")
            assert row["email"] == "reauth@example.com"
            assert row["id"] == "first"

    async def test_collision_preserves_transaction(
        self, sqlalchemy_integration_engine, table
    ):
        async with sqlalchemy_integration_engine.begin() as connection:
            factor = make_factor(connection, table)
            enrollment = await factor.get_by_identity_id("second")
            assert enrollment is not None
            with pytest.raises(TokenIdentifierCollision):
                await factor.update(
                    dataclasses.replace(
                        enrollment,
                        password_hash="new",
                        reset_token_identifier="pending",
                    )
                )
            assert await factor.get_by_identity_id("second") == enrollment
            await factor.update(
                dataclasses.replace(
                    enrollment, password_hash="new", reset_token_identifier="different"
                )
            )
        async with sqlalchemy_integration_engine.connect() as connection:
            assert (
                await connection.scalar(
                    sqlalchemy.select(table.c.password_hash).where(
                        table.c.id == "second"
                    )
                )
                == "new"
            )

    async def test_other_integrity_error(self, sqlalchemy_integration_engine, table):
        async with sqlalchemy_integration_engine.begin() as connection:
            factor = make_factor(connection, table)
            enrollment = await factor.get_by_identity_id("second")
            assert enrollment is not None
            with pytest.raises(sqlalchemy.exc.IntegrityError):
                await factor.update(
                    dataclasses.replace(enrollment, reset_token_verifier="verifier")
                )
            assert await factor.get_by_identity_id("second") == enrollment

    async def test_password_reset_flow(self, sqlalchemy_integration_engine, table):
        async with sqlalchemy_integration_engine.begin() as connection:
            factor = make_factor(connection, table)
            await factor.enroll("second", "original")
            token = await factor.forgot_password("second")
        async with sqlalchemy_integration_engine.begin() as connection:
            factor = make_factor(connection, table)
            await factor.reset_password(token, "new")
        async with sqlalchemy_integration_engine.begin() as connection:
            factor = make_factor(connection, table)
            assert (await factor.verify("second", "new")).identity_id == "second"
            with pytest.raises(InvalidPasswordResetTokenException):
                await factor.reset_password(token, "other")

    async def test_concurrent_reset_rejects_replay(
        self, sqlalchemy_integration_engine, table
    ):
        if sqlalchemy_integration_engine.dialect.name == "sqlite":
            pytest.skip("SQLite does not support SELECT FOR UPDATE")
        async with sqlalchemy_integration_engine.begin() as connection:
            factor = make_factor(connection, table)
            generated = await factor.token_provider.generate()
            await connection.execute(
                sqlalchemy.update(table)
                .where(table.c.id == "first")
                .values(
                    reset_token_identifier=generated.identifier,
                    reset_token_verifier=generated.verifier,
                    reset_token_expires_at=4102444800,
                )
            )
        attempted = anyio.Event()
        finished = anyio.Event()

        async def reset_again():
            async with sqlalchemy_integration_engine.begin() as connection:
                factor = make_factor(connection, table)
                attempted.set()
                with pytest.raises(InvalidPasswordResetTokenException):
                    await factor.reset_password(generated.token, "other")
                finished.set()

        with anyio.fail_after(10):
            async with sqlalchemy_integration_engine.connect() as connection:
                transaction = await connection.begin()
                await make_factor(connection, table).reset_password(
                    generated.token, "new"
                )
                async with anyio.create_task_group() as tasks:
                    tasks.start_soon(reset_again)
                    await attempted.wait()
                    with anyio.move_on_after(0.1):
                        await finished.wait()
                    assert not finished.is_set()
                    await transaction.commit()
                assert finished.is_set()
