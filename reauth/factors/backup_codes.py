import abc
import dataclasses
import secrets
import typing

from reauth.amr import AuthenticationMethodReference
from reauth.crypto import get_token_hash
from reauth.exceptions import ReauthException
from reauth.factors.base import FactorBase
from reauth.logging import get_logger

logger = get_logger(__name__)


@dataclasses.dataclass
class BackupCodesEnrollment:
    """Enrollment data for backup codes factor."""

    id: typing.Any | None
    identity_id: typing.Any
    codes_hashes: list[str]
    used_codes_hashes: list[str]


class BackupCodesException(ReauthException):
    """Base exception for backup codes errors."""


class InvalidBackupCodeException(BackupCodesException):
    """Raised when a backup code is invalid."""


class AlreadyUsedBackupCodeException(BackupCodesException):
    """Raised when a backup code has already been used."""


class NotEnrolledBackupCodesException(BackupCodesException):
    """Raised when trying to verify backup codes for an identity with no enrollment."""


class AlreadyEnrolledBackupCodesException(BackupCodesException):
    """Raised when trying to enroll an identity that already has backup codes."""


# Default character set: uppercase letters and digits, excluding ambiguous characters
# Excludes: 0 (zero), O (letter O), 1 (one), I (letter I), l (lowercase L)
DEFAULT_CHARS: str = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


class BackupCodesFactor(FactorBase[BackupCodesEnrollment], abc.ABC):
    """
    Factor for backup codes authentication.

    Backup codes are single-use, randomly generated codes that serve as a
    fallback authentication method when primary factors are unavailable.
    """

    AMR: typing.ClassVar[AuthenticationMethodReference] = (
        AuthenticationMethodReference.OTP
    )

    def __init__(
        self,
        *,
        hash_secret: str,
        code_length: int = 10,
        code_count: int = 10,
        chars: str = DEFAULT_CHARS,
        identifier: str = "backup_codes",
        step: int = 1,
    ) -> None:
        """
        Initialize the backup codes factor.

        Args:
            hash_secret: Secret key used for hashing backup codes.
            code_length: Length of each backup code (default: 10).
            code_count: Number of backup codes to generate (default: 10).
            chars: Character set for code generation (default: excludes ambiguous chars).
            identifier: Unique identifier for the factor (default: "backup_codes").
            step: Authentication step at which this factor can be used (default: 1).
        """
        super().__init__(identifier=identifier, step=step)
        self.hash_secret = hash_secret
        self.code_length = code_length
        self.code_count = code_count
        self.chars = chars

    async def enroll(
        self, identity_id: typing.Any
    ) -> tuple[list[str], BackupCodesEnrollment]:
        """
        Enroll backup codes for a given identity.

        Generates a set of random backup codes, hashes them, and persists the enrollment.
        If an existing enrollment exists, it is deleted and replaced with the new one.

        Args:
            identity_id: The ID of the identity to enroll backup codes for.

        Returns:
            A tuple of (plaintext_codes, enrollment) where:
            - plaintext_codes: List of plaintext backup codes to display to the user
            - enrollment: The persisted BackupCodesEnrollment object
        """
        logger.debug(
            "Backup codes enroll attempted", extra={"identity_id": identity_id}
        )

        # Check for existing enrollment and delete it
        existing = await self.get_enrollment(identity_id)
        if existing is not None:
            logger.info(
                "Backup codes enrollment replaced",
                extra={"identity_id": identity_id},
            )
            await self.delete(existing)

        # Generate plaintext codes
        plaintext_codes: list[str] = [
            "".join(secrets.choice(self.chars) for _ in range(self.code_length))
            for _ in range(self.code_count)
        ]

        # Hash all codes
        codes_hashes: list[str] = [
            get_token_hash(code, secret=self.hash_secret) for code in plaintext_codes
        ]

        # Create enrollment with hashed codes
        enrollment = BackupCodesEnrollment(
            id=None,
            identity_id=identity_id,
            codes_hashes=codes_hashes,
            used_codes_hashes=[],
        )

        # Persist
        enrollment.id = await self.insert(enrollment)

        logger.info(
            "Backup codes enrollment created",
            extra={"identity_id": identity_id, "code_count": self.code_count},
        )

        return (plaintext_codes, enrollment)

    async def verify(self, identity_id: typing.Any, code: str) -> BackupCodesEnrollment:
        """
        Verify a backup code for a given identity.

        Args:
            identity_id: The ID of the identity to verify the backup code for.
            code: The backup code provided by the user.

        Returns:
            The updated BackupCodesEnrollment with the used code tracked.

        Raises:
            NotEnrolledBackupCodesException: If the identity has no backup codes enrollment.
            InvalidBackupCodeException: If the code is invalid.
            AlreadyUsedBackupCodeException: If the code has already been used.
        """
        logger.debug(
            "Backup codes verification attempted", extra={"identity_id": identity_id}
        )

        enrollment = await self.get_enrollment(identity_id)
        if enrollment is None:
            logger.warning(
                "Backup codes verify failed: not enrolled",
                extra={"identity_id": identity_id},
            )
            raise NotEnrolledBackupCodesException()

        # Hash the provided code
        code_hash = get_token_hash(code, secret=self.hash_secret)

        # Check if code is valid and unused
        if code_hash not in enrollment.codes_hashes:
            logger.warning(
                "Backup codes verify failed: invalid code",
                extra={"identity_id": identity_id},
            )
            raise InvalidBackupCodeException()

        if code_hash in enrollment.used_codes_hashes:
            logger.warning(
                "Backup codes verify failed: code already used",
                extra={"identity_id": identity_id},
            )
            raise AlreadyUsedBackupCodeException()

        # Mark code as used
        enrollment.used_codes_hashes = list(enrollment.used_codes_hashes) + [code_hash]
        await self.update(enrollment)

        logger.info(
            "Backup codes verification successful", extra={"identity_id": identity_id}
        )
        return enrollment

    @abc.abstractmethod
    async def insert(self, backup_codes: BackupCodesEnrollment) -> typing.Any:
        """Insert a backup codes enrollment into a persistent store."""
        ...

    @abc.abstractmethod
    async def update(self, backup_codes: BackupCodesEnrollment) -> None:
        """Update a backup codes enrollment in the persistent store."""
        ...

    @abc.abstractmethod
    async def delete(self, backup_codes: BackupCodesEnrollment) -> None:
        """Delete a backup codes enrollment from the persistent store."""
        ...
