from collections.abc import AsyncGenerator

import pytest
from sqlalchemy import (
    JSON,
    Column,
    Integer,
    MetaData,
    Table,
)
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine
from sqlalchemy.sql.expression import delete, insert, select, update

from reauth.factors.backup_codes import (
    AlreadyUsedBackupCodeException,
    BackupCodesEnrollment,
    BackupCodesFactor,
    InvalidBackupCodeException,
    NotEnrolledBackupCodesException,
)

sqlalchemy_meta = MetaData()
backup_codes_table = Table(
    "backup_codes",
    sqlalchemy_meta,
    Column("id", Integer, primary_key=True),
    Column("identity_id", Integer, nullable=False),
    Column("codes_hashes", JSON, nullable=False),
    Column("used_codes_hashes", JSON, nullable=False),
    sqlite_autoincrement=True,
)


class SQLAlchemyBackupCodesFactor(BackupCodesFactor):
    """Concrete implementation of BackupCodesFactor using SQLAlchemy."""

    def __init__(
        self,
        connection: AsyncConnection,
        *,
        hash_secret: str = "test-secret",
        code_length: int = 10,
        code_count: int = 10,
        chars: str = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789",
        identifier: str = "backup_codes",
        step: int = 1,
    ) -> None:
        self.connection = connection
        super().__init__(
            hash_secret=hash_secret,
            code_length=code_length,
            code_count=code_count,
            chars=chars,
            identifier=identifier,
            step=step,
        )

    async def get_enrollment(self, identity_id: int) -> BackupCodesEnrollment | None:
        """Retrieve the backup codes enrollment for a given identity."""
        result = await self.connection.execute(
            select(backup_codes_table).where(
                backup_codes_table.c.identity_id == identity_id
            )
        )
        row = result.fetchone()
        if row is None:
            return None
        return BackupCodesEnrollment(
            id=row.id,
            identity_id=row.identity_id,
            codes_hashes=row.codes_hashes,
            used_codes_hashes=row.used_codes_hashes,
        )

    async def insert(self, backup_codes: BackupCodesEnrollment) -> int:
        """Insert a backup codes enrollment into the database."""
        result = await self.connection.execute(
            insert(backup_codes_table)
            .values(
                identity_id=backup_codes.identity_id,
                codes_hashes=backup_codes.codes_hashes,
                used_codes_hashes=backup_codes.used_codes_hashes,
            )
            .returning(backup_codes_table.c.id)
        )
        return result.scalar_one()

    async def update(self, backup_codes: BackupCodesEnrollment) -> None:
        """Update an existing backup codes enrollment in the database."""
        await self.connection.execute(
            update(backup_codes_table)
            .where(backup_codes_table.c.id == backup_codes.id)
            .values(
                codes_hashes=backup_codes.codes_hashes,
                used_codes_hashes=backup_codes.used_codes_hashes,
            )
        )

    async def delete(self, backup_codes: BackupCodesEnrollment) -> None:
        """Delete a backup codes enrollment from the database."""
        await self.connection.execute(
            delete(backup_codes_table).where(backup_codes_table.c.id == backup_codes.id)
        )


@pytest.fixture
async def sqlalchemy_connection(
    sqlalchemy_engine: AsyncEngine,
) -> AsyncGenerator[AsyncConnection]:
    """Fixture that creates tables and provides a connection for testing."""
    async with sqlalchemy_engine.begin() as conn:
        await conn.run_sync(sqlalchemy_meta.create_all)
        yield conn
        await conn.run_sync(sqlalchemy_meta.drop_all)


@pytest.fixture
def backup_codes_factor(
    sqlalchemy_connection: AsyncConnection,
) -> SQLAlchemyBackupCodesFactor:
    """Fixture providing a BackupCodesFactor instance."""
    return SQLAlchemyBackupCodesFactor(sqlalchemy_connection)


@pytest.mark.anyio
class TestBackupCodesEnroll:
    """Tests for backup codes enrollment."""

    async def test_enroll_creates_codes(
        self, backup_codes_factor: SQLAlchemyBackupCodesFactor
    ) -> None:
        """Test that enroll creates backup codes."""
        plaintext_codes, enrollment = await backup_codes_factor.enroll(identity_id=1)

        assert len(plaintext_codes) == 10
        assert len(enrollment.codes_hashes) == 10
        assert enrollment.used_codes_hashes == []
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
        self, backup_codes_factor: SQLAlchemyBackupCodesFactor
    ) -> None:
        """Test that enroll overwrites existing backup codes."""
        # First enrollment
        first_codes, first_enrollment = await backup_codes_factor.enroll(identity_id=1)
        first_hashes = first_enrollment.codes_hashes

        # Second enrollment
        second_codes, second_enrollment = await backup_codes_factor.enroll(
            identity_id=1
        )
        second_hashes = second_enrollment.codes_hashes

        # Codes should be different
        assert first_codes != second_codes
        assert first_hashes != second_hashes

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
            code_length=8,
            code_count=5,
            chars="ABC123",
        )
        plaintext_codes, enrollment = await factor.enroll(identity_id=1)

        assert len(plaintext_codes) == 5
        assert len(enrollment.codes_hashes) == 5
        for code in plaintext_codes:
            assert len(code) == 8
            assert all(c in "ABC123" for c in code)


@pytest.mark.anyio
class TestBackupCodesVerify:
    """Tests for backup codes verification."""

    async def test_verify_valid_code(
        self, backup_codes_factor: SQLAlchemyBackupCodesFactor
    ) -> None:
        """Test that verify accepts a valid code."""
        plaintext_codes, _ = await backup_codes_factor.enroll(identity_id=1)

        # Verify first code
        result = await backup_codes_factor.verify(
            identity_id=1, code=plaintext_codes[0]
        )

        assert result.identity_id == 1
        assert len(result.used_codes_hashes) == 1

    async def test_verify_invalid_code(
        self, backup_codes_factor: SQLAlchemyBackupCodesFactor
    ) -> None:
        """Test that verify rejects an invalid code."""
        await backup_codes_factor.enroll(identity_id=1)

        with pytest.raises(InvalidBackupCodeException):
            await backup_codes_factor.verify(identity_id=1, code="INVALID_CODE")

    async def test_verify_used_code(
        self, backup_codes_factor: SQLAlchemyBackupCodesFactor
    ) -> None:
        """Test that verify rejects an already used code."""
        plaintext_codes, _ = await backup_codes_factor.enroll(identity_id=1)

        # Use first code
        await backup_codes_factor.verify(identity_id=1, code=plaintext_codes[0])

        # Try to use it again
        with pytest.raises(AlreadyUsedBackupCodeException):
            await backup_codes_factor.verify(identity_id=1, code=plaintext_codes[0])

    async def test_verify_not_enrolled(
        self, backup_codes_factor: SQLAlchemyBackupCodesFactor
    ) -> None:
        """Test that verify raises for non-enrolled identity."""
        with pytest.raises(NotEnrolledBackupCodesException):
            await backup_codes_factor.verify(identity_id=999, code="SOME_CODE")

    async def test_verify_multiple_codes(
        self, backup_codes_factor: SQLAlchemyBackupCodesFactor
    ) -> None:
        """Test that multiple codes can be verified."""
        plaintext_codes, _ = await backup_codes_factor.enroll(identity_id=1)

        # Verify first two codes
        await backup_codes_factor.verify(identity_id=1, code=plaintext_codes[0])
        await backup_codes_factor.verify(identity_id=1, code=plaintext_codes[1])

        # Get current enrollment
        enrollment = await backup_codes_factor.get_enrollment(identity_id=1)
        assert enrollment is not None
        assert len(enrollment.used_codes_hashes) == 2

    async def test_verify_remaining_codes_unused(
        self, backup_codes_factor: SQLAlchemyBackupCodesFactor
    ) -> None:
        """Test that unused codes remain available."""
        plaintext_codes, _ = await backup_codes_factor.enroll(identity_id=1)

        # Verify first code
        await backup_codes_factor.verify(identity_id=1, code=plaintext_codes[0])

        # Second code should still work
        result = await backup_codes_factor.verify(
            identity_id=1, code=plaintext_codes[1]
        )
        assert result.identity_id == 1
