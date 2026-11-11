import dataclasses
import uuid
from collections.abc import AsyncGenerator

import anyio
import pytest
import sqlalchemy
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from reauth.amr import AuthenticationMethodReference
from reauth.identity_session import IdentitySession, ReusedRefreshTokenException
from reauth.integrations.sqlalchemy import (
    InvalidSessionFamilyException,
    MissingTransactionException,
    SQLAlchemyIdentitySessionService,
    create_identity_session_table,
)
from reauth.timestamp import get_current_timestamp
from reauth.tokens import (
    ChecksummedTokenProvider,
    HMACTokenVerifier,
    TokenIdentifierCollision,
)


def make_service(
    connection: AsyncConnection, table: sqlalchemy.Table
) -> SQLAlchemyIdentitySessionService:
    verifier = HMACTokenVerifier(current_key_id="test", keys={"test": b"t" * 32})
    return SQLAlchemyIdentitySessionService(
        connection,
        table,
        token_provider=ChecksummedTokenProvider(prefix="reauth_is_", verifier=verifier),
        refresh_token_provider=ChecksummedTokenProvider(
            prefix="reauth_isr_", verifier=verifier
        ),
    )


@pytest.fixture
async def table(
    sqlalchemy_integration_engine: AsyncEngine,
) -> AsyncGenerator[sqlalchemy.Table]:
    metadata = sqlalchemy.MetaData()
    table = create_identity_session_table(metadata)
    async with sqlalchemy_integration_engine.begin() as connection:
        await connection.run_sync(metadata.create_all)
    try:
        yield table
    finally:
        async with sqlalchemy_integration_engine.begin() as connection:
            await connection.run_sync(metadata.drop_all)


@pytest.fixture
def session() -> IdentitySession:
    return IdentitySession(
        id=None,
        identity_id=1,
        token_identifier="root-access",
        token_verifier="access-verifier",
        expires_at=get_current_timestamp() + 3600,
        amr=[AuthenticationMethodReference.PWD],
        context={"device": "laptop"},
        refresh_token_identifier="root-refresh",
        refresh_token_verifier="refresh-verifier",
        refresh_token_expires_at=get_current_timestamp() + 7200,
    )


def replacement(session: IdentitySession) -> IdentitySession:
    return dataclasses.replace(
        session,
        id=None,
        token_identifier="new-access",
        refresh_token_identifier="new-refresh",
        token_verifier="new-access-verifier",
        refresh_token_verifier="new-refresh-verifier",
        family_id=None,
        replaced_by_id=None,
        revoked_at=None,
    )


@pytest.fixture
async def family(
    sqlalchemy_integration_engine: AsyncEngine,
    table: sqlalchemy.Table,
    session: IdentitySession,
) -> list[IdentitySession]:
    root = dataclasses.replace(session, id=42, family_id=42, replaced_by_id=43)
    child = dataclasses.replace(
        session,
        id=43,
        family_id=42,
        token_identifier="child-access",
        refresh_token_identifier="child-refresh",
    )
    async with sqlalchemy_integration_engine.begin() as connection:
        await connection.execute(
            sqlalchemy.insert(table),
            [dataclasses.asdict(root), dataclasses.asdict(child)],
        )
    return [root, child]


@pytest.fixture
async def refreshable_family(
    sqlalchemy_integration_engine: AsyncEngine,
    table: sqlalchemy.Table,
    family: list[IdentitySession],
) -> tuple[list[IdentitySession], list[str]]:
    sessions = []
    tokens = []
    async with sqlalchemy_integration_engine.begin() as connection:
        service = make_service(connection, table)
        for member in family:
            generated = await service.refresh_token_provider.generate()
            stored = dataclasses.replace(
                member,
                refresh_token_identifier=generated.identifier,
                refresh_token_verifier=generated.verifier,
            )
            await connection.execute(
                sqlalchemy.update(table)
                .where(table.c.id == member.id)
                .values(
                    refresh_token_identifier=stored.refresh_token_identifier,
                    refresh_token_verifier=stored.refresh_token_verifier,
                )
            )
            sessions.append(stored)
            tokens.append(generated.token)
    return sessions, tokens


@pytest.mark.anyio
class TestSQLAlchemyIdentitySession:
    async def test_requires_transaction(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        table: sqlalchemy.Table,
        session: IdentitySession,
    ) -> None:
        async with sqlalchemy_integration_engine.connect() as connection:
            with pytest.raises(MissingTransactionException):
                make_service(connection, table)
            async with connection.begin():
                service = make_service(connection, table)
            for operation in (
                lambda: service.insert(session),
                lambda: service.get_by_token_identifier("root-access"),
                lambda: service.get_by_refresh_token_identifier("root-refresh"),
                lambda: service.update_verifier(session),
                lambda: service.replace(session, replacement(session)),
                lambda: service.revoke_family(session),
            ):
                with pytest.raises(MissingTransactionException):
                    await operation()
                assert not connection.in_transaction()

    @pytest.mark.parametrize("record_id", [None, 42])
    @pytest.mark.parametrize("commit", [False, True])
    async def test_initial_insert_transaction_ownership(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        table: sqlalchemy.Table,
        session: IdentitySession,
        record_id: int | None,
        commit: bool,
    ) -> None:
        session.id = record_id
        async with sqlalchemy_integration_engine.connect() as connection:
            transaction = await connection.begin()
            session_id = await make_service(connection, table).insert(session)
            assert session.id == record_id
            assert session.family_id is None
            assert session_id is not None
            if record_id is not None:
                assert session_id == record_id
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
                    **dataclasses.asdict(session),
                    "id": session_id,
                    "family_id": session_id,
                }
            else:
                assert row is None

    async def test_custom_ids_and_application_columns(
        self, sqlalchemy_integration_engine: AsyncEngine, session: IdentitySession
    ) -> None:
        metadata = sqlalchemy.MetaData()
        table = create_identity_session_table(
            metadata, id_type=sqlalchemy.Uuid(), identity_id_type=sqlalchemy.Uuid()
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
        async with sqlalchemy_integration_engine.begin() as connection:
            await connection.run_sync(metadata.create_all)
        try:
            async with sqlalchemy_integration_engine.begin() as connection:
                service = make_service(connection, table)
                session.identity_id = uuid.uuid4()
                session.id = await service.insert(session)
                session.family_id = session.id
                assert isinstance(session.id, uuid.UUID)
                assert (
                    await service.get_by_token_identifier(session.token_identifier)
                    == session
                )
                new = replacement(session)
                new.id = await service.replace(session, new)
                assert isinstance(new.id, uuid.UUID)
                stored = await service.get_by_token_identifier(new.token_identifier)
                assert stored is not None and stored.family_id == session.id
                assert stored.amr == [AuthenticationMethodReference.PWD]
                assert isinstance(stored.amr[0], AuthenticationMethodReference)
                row = (
                    (
                        await connection.execute(
                            sqlalchemy.select(table).where(table.c.id == new.id)
                        )
                    )
                    .mappings()
                    .one()
                )
                assert row["application_state"] == "pending"
                assert row["family_id"] == session.id
        finally:
            async with sqlalchemy_integration_engine.begin() as connection:
                await connection.run_sync(metadata.drop_all)

    @pytest.mark.parametrize("key", ["access", "refresh"])
    async def test_identifier_collision_preserves_transaction(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        table: sqlalchemy.Table,
        family: list[IdentitySession],
        key: str,
    ) -> None:
        new = replacement(family[1])
        if key == "access":
            new.token_identifier = family[0].token_identifier
        else:
            new.refresh_token_identifier = family[0].refresh_token_identifier
        async with sqlalchemy_integration_engine.begin() as connection:
            service = make_service(connection, table)
            with pytest.raises(TokenIdentifierCollision):
                await service.insert(new)
            assert (
                await connection.scalar(
                    sqlalchemy.select(sqlalchemy.func.count()).select_from(table)
                )
                == 2
            )
            valid = replacement(family[1])
            valid_id = await service.insert(valid)
            stored = await service.get_by_token_identifier(valid.token_identifier)
            assert stored is not None and stored.family_id == valid_id

    @pytest.mark.parametrize("key", ["access", "refresh"])
    async def test_collision_lookup_does_not_wait_for_conflicting_row_lock(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        table: sqlalchemy.Table,
        family: list[IdentitySession],
        key: str,
    ) -> None:
        if sqlalchemy_integration_engine.dialect.name == "sqlite":
            pytest.skip("SQLite does not support SELECT FOR UPDATE")
        new = replacement(family[1])
        if key == "access":
            new.token_identifier = family[0].token_identifier
        else:
            new.refresh_token_identifier = family[0].refresh_token_identifier
        integrity_error = IntegrityError(None, None, Exception("duplicate identifier"))
        async with sqlalchemy_integration_engine.begin() as blocker:
            await blocker.execute(
                sqlalchemy.select(table.c.id)
                .where(table.c.id == family[0].id)
                .with_for_update()
            )
            async with sqlalchemy_integration_engine.begin() as connection:
                service = make_service(connection, table)
                # Isolate the diagnostic read from the INSERT's own uniqueness locks.
                with anyio.fail_after(5):
                    with pytest.raises(TokenIdentifierCollision) as error:
                        await service._raise_identifier_collision(new, integrity_error)
                assert error.value.__cause__ is integrity_error

    async def test_unrelated_integrity_error_preserves_transaction(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        table: sqlalchemy.Table,
        family: list[IdentitySession],
    ) -> None:
        new = dataclasses.replace(replacement(family[1]), id=42)
        async with sqlalchemy_integration_engine.begin() as connection:
            service = make_service(connection, table)
            with pytest.raises(IntegrityError):
                await service.insert(new)
            assert (
                await service.get_by_token_identifier(family[0].token_identifier)
                == family[0]
            )

    async def test_access_only_sessions_allow_multiple_null_refresh_identifiers(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        table: sqlalchemy.Table,
        session: IdentitySession,
    ) -> None:
        session.refresh_token_identifier = None
        session.refresh_token_verifier = None
        session.refresh_token_expires_at = None
        async with sqlalchemy_integration_engine.begin() as connection:
            service = make_service(connection, table)
            first_id = await service.insert(session)
            second_id = await service.insert(
                dataclasses.replace(session, token_identifier="another")
            )
            assert first_id != second_id

    async def test_insert_preserves_existing_family(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        table: sqlalchemy.Table,
        family: list[IdentitySession],
    ) -> None:
        new = dataclasses.replace(replacement(family[1]), family_id=42)
        async with sqlalchemy_integration_engine.begin() as connection:
            service = make_service(connection, table)
            new_id = await service.insert(new)
            stored = await service.get_by_token_identifier(new.token_identifier)
            assert stored is not None and stored.id == new_id and stored.family_id == 42

    @pytest.mark.parametrize("root_state", ["missing", "revoked", "invalid"])
    async def test_insert_rejects_unavailable_family(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        table: sqlalchemy.Table,
        family: list[IdentitySession],
        root_state: str,
    ) -> None:
        async with sqlalchemy_integration_engine.begin() as connection:
            if root_state == "missing":
                await connection.execute(
                    sqlalchemy.delete(table).where(table.c.id == 42)
                )
            else:
                values = (
                    {"revoked_at": 123}
                    if root_state == "revoked"
                    else {"family_id": 999}
                )
                await connection.execute(
                    sqlalchemy.update(table).where(table.c.id == 42).values(**values)
                )
        async with sqlalchemy_integration_engine.begin() as connection:
            new = dataclasses.replace(replacement(family[1]), family_id=42)
            with pytest.raises(InvalidSessionFamilyException):
                await make_service(connection, table).insert(new)
            assert (
                await connection.scalar(
                    sqlalchemy.select(table.c.id).where(
                        table.c.token_identifier == "new-access"
                    )
                )
                is None
            )

    @pytest.mark.parametrize(
        "state", [{"expires_at": 0}, {"revoked_at": 123}, {"replaced_by_id": 99}]
    )
    async def test_lookups_include_inactive_rows(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        table: sqlalchemy.Table,
        session: IdentitySession,
        state: dict[str, int],
    ) -> None:
        stored = dataclasses.replace(session, id=42, family_id=42, **state)
        async with sqlalchemy_integration_engine.begin() as connection:
            await connection.execute(
                sqlalchemy.insert(table).values(**dataclasses.asdict(stored))
            )
        async with sqlalchemy_integration_engine.begin() as connection:
            service = make_service(connection, table)
            assert await service.get_by_token_identifier("root-access") == stored
            assert (
                await service.get_by_refresh_token_identifier("root-refresh") == stored
            )
            assert await service.get_by_token_identifier("unknown") is None
            assert await service.get_by_refresh_token_identifier("unknown") is None

    async def test_lookups_fail_closed_for_missing_root(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        table: sqlalchemy.Table,
        session: IdentitySession,
    ) -> None:
        async with sqlalchemy_integration_engine.begin() as connection:
            await connection.execute(
                sqlalchemy.insert(table).values(
                    **dataclasses.asdict(
                        dataclasses.replace(session, id=43, family_id=42)
                    )
                )
            )
        async with sqlalchemy_integration_engine.begin() as connection:
            service = make_service(connection, table)
            assert await service.get_by_token_identifier("root-access") is None
            assert await service.get_by_refresh_token_identifier("root-refresh") is None

    async def test_update_verifier_changes_no_other_fields(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        table: sqlalchemy.Table,
        family: list[IdentitySession],
    ) -> None:
        original = family[1]
        async with sqlalchemy_integration_engine.begin() as connection:
            service = make_service(connection, table)
            protected = await service.get_by_token_identifier(original.token_identifier)
            assert protected is not None
            stale = dataclasses.replace(
                protected,
                token_verifier="upgraded",
                identity_id=999,
                expires_at=0,
                revoked_at=123,
                replaced_by_id=99,
                context={"stale": True},
            )
            await service.update_verifier(stale)
            assert await service.get_by_token_identifier(
                original.token_identifier
            ) == dataclasses.replace(original, token_verifier="upgraded")

    @pytest.mark.parametrize("commit", [False, True])
    @pytest.mark.parametrize("refresh", [False, True])
    async def test_replace_transaction_ownership(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        table: sqlalchemy.Table,
        family: list[IdentitySession],
        commit: bool,
        refresh: bool,
    ) -> None:
        previous = family[1]
        new = replacement(previous)
        if not refresh:
            new.refresh_token_identifier = None
            new.refresh_token_verifier = None
            new.refresh_token_expires_at = None
        async with sqlalchemy_integration_engine.connect() as connection:
            transaction = await connection.begin()
            new_id = await make_service(connection, table).replace(previous, new)
            assert new_id is not None
            async with sqlalchemy_integration_engine.connect() as observer:
                rows = (
                    (
                        await observer.execute(
                            sqlalchemy.select(table).order_by(table.c.id)
                        )
                    )
                    .mappings()
                    .all()
                )
                assert [dict(row) for row in rows] == [
                    dataclasses.asdict(member) for member in family
                ]
            if commit:
                await transaction.commit()
            else:
                await transaction.rollback()
        async with sqlalchemy_integration_engine.begin() as connection:
            service = make_service(connection, table)
            stored_previous = await service.get_by_token_identifier(
                previous.token_identifier
            )
            expected_previous = (
                dataclasses.replace(previous, replaced_by_id=new_id)
                if commit
                else previous
            )
            assert stored_previous == expected_previous
            stored_new = await service.get_by_token_identifier(new.token_identifier)
            if commit:
                assert stored_new == dataclasses.replace(new, id=new_id, family_id=42)
            else:
                assert stored_new is None
            assert (
                await service.get_by_token_identifier(family[0].token_identifier)
                == family[0]
            )

    @pytest.mark.parametrize(
        "scenario",
        [
            "missing_root",
            "revoked_root",
            "invalid_root",
            "missing_previous",
            "revoked_previous",
            "replaced_previous",
            "changed_identifier",
            "changed_verifier",
            "expired",
            "disabled",
            "wrong_family",
            "no_family",
        ],
    )
    async def test_replace_rechecks_eligibility(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        table: sqlalchemy.Table,
        family: list[IdentitySession],
        scenario: str,
    ) -> None:
        previous = family[1]
        async with sqlalchemy_integration_engine.begin() as connection:
            if scenario in {"missing_root", "missing_previous"}:
                await connection.execute(
                    sqlalchemy.delete(table).where(
                        table.c.id == (42 if scenario == "missing_root" else 43)
                    )
                )
            elif scenario == "no_family":
                previous = dataclasses.replace(previous, family_id=None)
            else:
                changes = {
                    "revoked_root": (42, {"revoked_at": 123}),
                    "invalid_root": (42, {"family_id": 999}),
                    "revoked_previous": (43, {"revoked_at": 123}),
                    "replaced_previous": (43, {"replaced_by_id": 99}),
                    "changed_identifier": (43, {"refresh_token_identifier": "changed"}),
                    "changed_verifier": (43, {"refresh_token_verifier": "changed"}),
                    "expired": (43, {"refresh_token_expires_at": 0}),
                    "disabled": (
                        43,
                        {
                            "refresh_token_identifier": None,
                            "refresh_token_verifier": None,
                        },
                    ),
                    "wrong_family": (43, {"family_id": 43}),
                }
                session_id, values = changes[scenario]
                await connection.execute(
                    sqlalchemy.update(table)
                    .where(table.c.id == session_id)
                    .values(**values)
                )
        async with sqlalchemy_integration_engine.begin() as connection:
            before = (
                (
                    await connection.execute(
                        sqlalchemy.select(table).order_by(table.c.id)
                    )
                )
                .mappings()
                .all()
            )
            assert (
                await make_service(connection, table).replace(
                    previous, replacement(previous)
                )
                is None
            )
            after = (
                (
                    await connection.execute(
                        sqlalchemy.select(table).order_by(table.c.id)
                    )
                )
                .mappings()
                .all()
            )
            assert before == after

    @pytest.mark.parametrize("key", ["access", "refresh"])
    async def test_replace_collision_is_atomic_and_retryable(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        table: sqlalchemy.Table,
        family: list[IdentitySession],
        key: str,
    ) -> None:
        new = replacement(family[1])
        if key == "access":
            new.token_identifier = family[0].token_identifier
        else:
            new.refresh_token_identifier = family[0].refresh_token_identifier
        async with sqlalchemy_integration_engine.begin() as connection:
            service = make_service(connection, table)
            with pytest.raises(TokenIdentifierCollision):
                await service.replace(family[1], new)
            assert (
                await connection.scalar(
                    sqlalchemy.select(sqlalchemy.func.count()).select_from(table)
                )
                == 2
            )
            assert (
                await service.get_by_token_identifier(family[1].token_identifier)
                == family[1]
            )
            assert await service.replace(family[1], replacement(family[1])) is not None

    async def test_replace_rolls_back_insert_when_link_update_fails(
        self, sqlalchemy_integration_engine: AsyncEngine, family: list[IdentitySession]
    ) -> None:
        metadata = sqlalchemy.MetaData()
        table = create_identity_session_table(metadata, name="constrained_sessions")
        table.append_constraint(
            sqlalchemy.CheckConstraint("replaced_by_id IS NULL OR replaced_by_id >= 40")
        )
        async with sqlalchemy_integration_engine.begin() as connection:
            await connection.run_sync(metadata.create_all)
            await connection.execute(
                sqlalchemy.insert(table),
                [dataclasses.asdict(member) for member in family],
            )
        try:
            async with sqlalchemy_integration_engine.begin() as connection:
                service = make_service(connection, table)
                with pytest.raises(DBAPIError) as error:
                    await service.replace(
                        family[1], dataclasses.replace(replacement(family[1]), id=7)
                    )
                assert "check" in str(error.value.orig).lower()
                rows = (
                    (
                        await connection.execute(
                            sqlalchemy.select(table).order_by(table.c.id)
                        )
                    )
                    .mappings()
                    .all()
                )
                assert [dict(row) for row in rows] == [
                    dataclasses.asdict(member) for member in family
                ]
        finally:
            async with sqlalchemy_integration_engine.begin() as connection:
                await connection.run_sync(metadata.drop_all)

    @pytest.mark.parametrize("commit", [False, True])
    async def test_revoke_preserves_timestamps_lineage_and_other_families(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        table: sqlalchemy.Table,
        family: list[IdentitySession],
        commit: bool,
    ) -> None:
        original = [family[0], dataclasses.replace(family[1], revoked_at=50)]
        independent = dataclasses.replace(
            family[1],
            id=90,
            family_id=90,
            token_identifier="independent-access",
            refresh_token_identifier="independent-refresh",
        )
        async with sqlalchemy_integration_engine.begin() as connection:
            await connection.execute(
                sqlalchemy.update(table).where(table.c.id == 43).values(revoked_at=50)
            )
            await connection.execute(
                sqlalchemy.insert(table).values(**dataclasses.asdict(independent))
            )
        async with sqlalchemy_integration_engine.connect() as connection:
            transaction = await connection.begin()
            await make_service(connection, table).revoke_family(
                dataclasses.replace(family[1], revoked_at=200)
            )
            if commit:
                await transaction.commit()
            else:
                await transaction.rollback()
        async with sqlalchemy_integration_engine.begin() as connection:
            service = make_service(connection, table)
            for member in original:
                expected = (
                    dataclasses.replace(member, revoked_at=200)
                    if commit and member.revoked_at is None
                    else member
                )
                assert (
                    await service.get_by_token_identifier(member.token_identifier)
                    == expected
                )
            assert (
                await service.get_by_token_identifier(independent.token_identifier)
                == independent
            )
            if commit:
                await service.revoke_family(
                    dataclasses.replace(family[1], revoked_at=300)
                )
                assert await service.get_by_token_identifier(
                    family[0].token_identifier
                ) == dataclasses.replace(family[0], revoked_at=200)

    async def test_revoke_missing_family_is_noop(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        table: sqlalchemy.Table,
        family: list[IdentitySession],
    ) -> None:
        async with sqlalchemy_integration_engine.begin() as connection:
            service = make_service(connection, table)
            await service.revoke_family(
                dataclasses.replace(family[1], family_id=999, revoked_at=200)
            )
            assert (
                await service.get_by_token_identifier(family[1].token_identifier)
                == family[1]
            )

    @pytest.mark.parametrize("lookup", ["access", "refresh"])
    async def test_lookup_locks_family_before_child(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        table: sqlalchemy.Table,
        family: list[IdentitySession],
        lookup: str,
    ) -> None:
        if sqlalchemy_integration_engine.dialect.name == "sqlite":
            pytest.skip("SQLite does not support SELECT FOR UPDATE")
        async with (
            sqlalchemy_integration_engine.connect() as first,
            sqlalchemy_integration_engine.begin() as second,
        ):
            transaction = await first.begin()
            service = make_service(first, table)
            if lookup == "access":
                assert (
                    await service.get_by_token_identifier("child-access") == family[1]
                )
            else:
                assert (
                    await service.get_by_refresh_token_identifier("child-refresh")
                    == family[1]
                )
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
                    await second.execute(
                        sqlalchemy.select(table.c.id)
                        .where(table.c.id == 42)
                        .with_for_update()
                    )
                assert error.value.orig is not None
                if second.dialect.name == "postgresql":
                    assert getattr(error.value.orig, "sqlstate", None) == "55P03"
                else:
                    assert error.value.orig.args[0] == 1205
                await savepoint.rollback()
            await transaction.commit()
            assert (
                await second.scalar(
                    sqlalchemy.select(table.c.id)
                    .where(table.c.id == 42)
                    .with_for_update()
                )
                == 42
            )

    @pytest.mark.parametrize("first_action", ["replace", "revoke"])
    async def test_replacement_and_revocation_serialize(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        table: sqlalchemy.Table,
        family: list[IdentitySession],
        first_action: str,
    ) -> None:
        if sqlalchemy_integration_engine.dialect.name == "sqlite":
            pytest.skip("SQLite does not support SELECT FOR UPDATE")
        revoked = dataclasses.replace(family[1], revoked_at=200)
        async with (
            sqlalchemy_integration_engine.connect() as first,
            sqlalchemy_integration_engine.begin() as second,
        ):
            transaction = await first.begin()
            first_service = make_service(first, table)
            second_service = make_service(second, table)
            if first_action == "replace":
                assert (
                    await first_service.replace(family[1], replacement(family[1]))
                    is not None
                )
            else:
                await first_service.revoke_family(revoked)
            if second.dialect.name == "postgresql":
                await second.execute(
                    sqlalchemy.text("SET LOCAL lock_timeout = '100ms'")
                )
            else:
                await second.execute(
                    sqlalchemy.text("SET SESSION innodb_lock_wait_timeout = 1")
                )
            async with second.begin_nested() as savepoint:
                operation = (
                    second_service.revoke_family(revoked)
                    if first_action == "replace"
                    else second_service.replace(family[1], replacement(family[1]))
                )
                with pytest.raises(DBAPIError) as error:
                    await operation
                assert error.value.orig is not None
                if second.dialect.name == "postgresql":
                    assert getattr(error.value.orig, "sqlstate", None) == "55P03"
                else:
                    assert error.value.orig.args[0] == 1205
                await savepoint.rollback()
            await transaction.commit()
            if first_action == "replace":
                await second_service.revoke_family(revoked)
            else:
                assert (
                    await second_service.replace(family[1], replacement(family[1]))
                    is None
                )
        async with sqlalchemy_integration_engine.connect() as connection:
            rows = (await connection.execute(sqlalchemy.select(table))).mappings().all()
            assert len(rows) == (3 if first_action == "replace" else 2)
            assert all(row["revoked_at"] == 200 for row in rows)

    @pytest.mark.parametrize("commit", [False, True])
    async def test_reuse_revocation_transaction_ownership(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        table: sqlalchemy.Table,
        refreshable_family: tuple[list[IdentitySession], list[str]],
        commit: bool,
    ) -> None:
        family, tokens = refreshable_family
        async with sqlalchemy_integration_engine.connect() as connection:
            transaction = await connection.begin()
            with pytest.raises(ReusedRefreshTokenException):
                await make_service(connection, table).refresh(tokens[0])
            if commit:
                await transaction.commit()
            else:
                await transaction.rollback()
        async with sqlalchemy_integration_engine.connect() as connection:
            rows = (
                (
                    await connection.execute(
                        sqlalchemy.select(table).order_by(table.c.id)
                    )
                )
                .mappings()
                .all()
            )
            for row, member in zip(rows, family, strict=True):
                assert (row["revoked_at"] is not None) == commit
                assert (
                    row["refresh_token_identifier"] == member.refresh_token_identifier
                )
                assert row["replaced_by_id"] == member.replaced_by_id

    async def test_concurrent_refresh_reuse_revokes_successor(
        self,
        sqlalchemy_integration_engine: AsyncEngine,
        table: sqlalchemy.Table,
        refreshable_family: tuple[list[IdentitySession], list[str]],
    ) -> None:
        if sqlalchemy_integration_engine.dialect.name == "sqlite":
            pytest.skip("SQLite does not support SELECT FOR UPDATE")
        _, tokens = refreshable_family
        async with (
            sqlalchemy_integration_engine.connect() as first,
            sqlalchemy_integration_engine.begin() as second,
        ):
            transaction = await first.begin()
            first_service = make_service(first, table)
            second_service = make_service(second, table)
            _, _, successor = await first_service.refresh(tokens[1])
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
                    await second_service.refresh(tokens[1])
                assert error.value.orig is not None
                if second.dialect.name == "postgresql":
                    assert getattr(error.value.orig, "sqlstate", None) == "55P03"
                else:
                    assert error.value.orig.args[0] == 1205
                await savepoint.rollback()
            await transaction.commit()
            with pytest.raises(ReusedRefreshTokenException):
                await second_service.refresh(tokens[1])
        async with sqlalchemy_integration_engine.connect() as connection:
            rows = (await connection.execute(sqlalchemy.select(table))).mappings().all()
            assert len(rows) == 3
            assert all(row["revoked_at"] is not None for row in rows)
            assert any(row["id"] == successor.id for row in rows)
