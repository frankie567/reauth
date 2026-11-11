import dataclasses
from collections.abc import AsyncGenerator

import pytest
from sqlalchemy import (
    MetaData,
)
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine
from sqlalchemy.sql.expression import insert, update

from reauth.factors.backup_codes import (
    AlreadyUsedBackupCodeException,
    BackupCodesEnrollment,
    InvalidBackupCodeException,
    NotEnrolledBackupCodesException,
)
from reauth.integrations.sqlalchemy import (
    SQLAlchemyBackupCodesFactor,
    create_backup_codes_enrollment_table,
)
from reauth.tokens import HMACTokenVerifier

sqlalchemy_meta = MetaData()
backup_codes_table = create_backup_codes_enrollment_table(sqlalchemy_meta)


@pytest.fixture
async def sqlalchemy_connection(
    sqlalchemy_integration_engine: AsyncEngine,
) -> AsyncGenerator[AsyncConnection]:
    """Fixture that creates tables and provides a connection for testing."""
    async with sqlalchemy_integration_engine.begin() as conn:
        await conn.run_sync(sqlalchemy_meta.create_all)
        yield conn
        await conn.run_sync(sqlalchemy_meta.drop_all)


@pytest.fixture
def backup_codes_factor(
    sqlalchemy_connection: AsyncConnection,
) -> SQLAlchemyBackupCodesFactor:
    """Fixture providing a BackupCodesFactor instance."""
    return SQLAlchemyBackupCodesFactor(
        sqlalchemy_connection,
        backup_codes_table,
        verifier=HMACTokenVerifier(current_key_id="test", keys={"test": b"t" * 32}),
    )


@pytest.fixture
async def backup_codes_data(
    backup_codes_factor: SQLAlchemyBackupCodesFactor,
) -> tuple[list[str], BackupCodesEnrollment]:
    plaintext_codes = ["BACKUP1234", "BACKUP5678"]
    enrollment = BackupCodesEnrollment(
        id=42,
        identity_id=1,
        codes=[
            await backup_codes_factor.verifier.create(code) for code in plaintext_codes
        ],
        used_codes=[],
    )
    await backup_codes_factor.connection.execute(
        insert(backup_codes_table).values(**dataclasses.asdict(enrollment))
    )
    return plaintext_codes, enrollment


@pytest.mark.anyio
class TestBackupCodesEnroll:
    """Tests for backup codes enrollment."""

    async def test_enroll_creates_codes(
        self, backup_codes_factor: SQLAlchemyBackupCodesFactor
    ) -> None:
        """Test that enroll creates backup codes."""
        plaintext_codes, enrollment = await backup_codes_factor.enroll(identity_id=1)

        assert len(plaintext_codes) == 10
        assert len(enrollment.codes) == 10
        assert enrollment.used_codes == []
        assert enrollment.identity_id == 1
        assert enrollment.id is not None

    async def test_enroll_returns_plaintext_codes(
        self, backup_codes_factor: SQLAlchemyBackupCodesFactor
    ) -> None:
        """Test that enroll returns plaintext codes."""
        plaintext_codes, _ = await backup_codes_factor.enroll(identity_id=1)

        # Verify all codes are strings of correct length
        for code in plaintext_codes:
            assert isinstance(code, str)
            assert len(code) == 10

    async def test_enroll_overwrites_existing(
        self,
        backup_codes_factor: SQLAlchemyBackupCodesFactor,
        backup_codes_data: tuple[list[str], BackupCodesEnrollment],
    ) -> None:
        """Test that enroll overwrites existing backup codes."""
        # First enrollment
        first_codes, first_enrollment = backup_codes_data
        first_entries = first_enrollment.codes

        # Second enrollment
        second_codes, second_enrollment = await backup_codes_factor.enroll(
            identity_id=1
        )
        second_entries = second_enrollment.codes

        # Codes should be different
        assert first_codes != second_codes
        assert first_entries != second_entries

        # Only one enrollment should exist
        current = await backup_codes_factor.get_enrollment(identity_id=1)
        assert current is not None
        assert current.id == second_enrollment.id

    async def test_enroll_custom_config(
        self, sqlalchemy_connection: AsyncConnection
    ) -> None:
        """Test enrollment with custom configuration."""
        factor = SQLAlchemyBackupCodesFactor(
            sqlalchemy_connection,
            backup_codes_table,
            verifier=HMACTokenVerifier(current_key_id="test", keys={"test": b"t" * 32}),
            code_length=8,
            code_count=5,
            chars="ABC123",
        )
        plaintext_codes, enrollment = await factor.enroll(identity_id=1)

        assert len(plaintext_codes) == 5
        assert len(enrollment.codes) == 5
        for code in plaintext_codes:
            assert len(code) == 8
            assert all(c in "ABC123" for c in code)


@pytest.mark.anyio
class TestBackupCodesVerify:
    """Tests for backup codes verification."""

    async def test_verify_valid_code(
        self,
        backup_codes_factor: SQLAlchemyBackupCodesFactor,
        backup_codes_data: tuple[list[str], BackupCodesEnrollment],
    ) -> None:
        """Test that verify accepts a valid code."""
        plaintext_codes, _ = backup_codes_data

        # Verify first code
        result = await backup_codes_factor.verify(
            identity_id=1, code=plaintext_codes[0]
        )

        assert result.identity_id == 1
        assert len(result.used_codes) == 1

    async def test_verify_invalid_code(
        self,
        backup_codes_factor: SQLAlchemyBackupCodesFactor,
        backup_codes_data: tuple[list[str], BackupCodesEnrollment],
    ) -> None:
        """Test that verify rejects an invalid code."""

        with pytest.raises(InvalidBackupCodeException):
            await backup_codes_factor.verify(identity_id=1, code="INVALID_CODE")

    async def test_verify_used_code(
        self,
        backup_codes_factor: SQLAlchemyBackupCodesFactor,
        backup_codes_data: tuple[list[str], BackupCodesEnrollment],
    ) -> None:
        """Test that verify rejects an already used code."""
        plaintext_codes, _ = backup_codes_data

        # Use first code
        await backup_codes_factor.connection.execute(
            update(backup_codes_table)
            .where(backup_codes_table.c.identity_id == 1)
            .values(used_codes=[backup_codes_data[1].codes[0]])
        )

        # Try to use it again
        with pytest.raises(AlreadyUsedBackupCodeException):
            await backup_codes_factor.verify(identity_id=1, code=plaintext_codes[0])

    async def test_verify_not_enrolled(
        self,
        backup_codes_factor: SQLAlchemyBackupCodesFactor,
    ) -> None:
        """Test that verify raises for non-enrolled identity."""
        with pytest.raises(NotEnrolledBackupCodesException):
            await backup_codes_factor.verify(identity_id=999, code="SOME_CODE")

    async def test_verify_multiple_codes(
        self,
        backup_codes_factor: SQLAlchemyBackupCodesFactor,
        backup_codes_data: tuple[list[str], BackupCodesEnrollment],
    ) -> None:
        """Test that multiple codes can be verified."""
        plaintext_codes, _ = backup_codes_data

        # Verify first two codes
        await backup_codes_factor.connection.execute(
            update(backup_codes_table)
            .where(backup_codes_table.c.identity_id == 1)
            .values(used_codes=[backup_codes_data[1].codes[0]])
        )
        await backup_codes_factor.verify(identity_id=1, code=plaintext_codes[1])

        # Get current enrollment
        enrollment = await backup_codes_factor.get_enrollment(identity_id=1)
        assert enrollment is not None
        assert len(enrollment.used_codes) == 2

    async def test_verify_remaining_codes_unused(
        self,
        backup_codes_factor: SQLAlchemyBackupCodesFactor,
        backup_codes_data: tuple[list[str], BackupCodesEnrollment],
    ) -> None:
        """Test that unused codes remain available."""
        plaintext_codes, _ = backup_codes_data

        # Verify first code
        await backup_codes_factor.connection.execute(
            update(backup_codes_table)
            .where(backup_codes_table.c.identity_id == 1)
            .values(used_codes=[backup_codes_data[1].codes[0]])
        )

        # Second code should still work
        result = await backup_codes_factor.verify(
            identity_id=1, code=plaintext_codes[1]
        )
        assert result.identity_id == 1
