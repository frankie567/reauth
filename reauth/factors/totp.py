import abc
import base64
import dataclasses
import functools
import secrets
import time
import typing

from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.twofactor import InvalidToken
from cryptography.hazmat.primitives.twofactor.totp import TOTP as CryptoTOTP

from reauth.amr import AuthenticationMethodReference
from reauth.exceptions import ReauthException
from reauth.factors.base import FactorBase
from reauth.logging import get_logger

logger = get_logger(__name__)

type TOTPAlgorithm = typing.Literal["sha1", "sha256", "sha512"]


def _get_algorithm(algorithm: TOTPAlgorithm) -> typing.Any:
    match algorithm:
        case "sha1":
            return SHA1()
        case "sha256":
            from cryptography.hazmat.primitives.hashes import SHA256

            return SHA256()
        case "sha512":
            from cryptography.hazmat.primitives.hashes import SHA512

            return SHA512()


@dataclasses.dataclass
class TOTPEnrollment:
    id: typing.Any | None
    identity_id: typing.Any
    enabled: bool
    secret: str
    algorithm: TOTPAlgorithm
    code_length: int
    time_step: int
    last_verified_time_step: int | None = None

    @functools.cached_property
    def _impl(self) -> CryptoTOTP:
        return CryptoTOTP(
            key=base64.b32decode(self.secret.encode("ascii")),
            length=self.code_length,
            algorithm=_get_algorithm(self.algorithm),
            time_step=self.time_step,
        )

    def get_provisioning_uri(
        self, account_name: str, issuer_name: str | None = None
    ) -> str:
        """
        Get the provisioning URI for this TOTP factor.

        Args:
            account_name: The name of the account (e.g., email or username).
            issuer_name: The name of the issuer (e.g., your service name).

        Returns:
            The provisioning URI that can be used to generate a QR code for enrollment in an authenticator app.
        """
        return self._impl.get_provisioning_uri(account_name, issuer_name)


class TOTPException(ReauthException):
    """Base exception for TOTP errors."""


class InvalidTOTPCodeException(TOTPException):
    """Raised when a TOTP code is invalid."""


class AlreadyEnabledTOTPException(TOTPException):
    """Raised when trying to enable an already enabled TOTP factor."""


class NotEnabledTOTPException(TOTPException):
    """Raised when trying to verify a TOTP factor that is not enabled."""


class AlreadyEnrolledTOTPException(TOTPException):
    """Raised when trying to enroll an identity that already has a TOTP enrollment."""


class NotEnrolledTOTPException(TOTPException):
    """Raised when trying to enable or verify a TOTP factor for an identity with no enrollment."""


class TOTPFactor(FactorBase[TOTPEnrollment], abc.ABC):
    AMR: typing.ClassVar[AuthenticationMethodReference] = (
        AuthenticationMethodReference.OTP
    )

    def __init__(
        self,
        *,
        code_length: int = 6,
        algorithm: TOTPAlgorithm = "sha256",
        time_step: int = 30,
        drift_tolerance: int = 1,
        identifier: str = "totp",
        step: int = 1,
    ) -> None:
        super().__init__(identifier=identifier, step=step)
        self.code_length = code_length
        self.algorithm: TOTPAlgorithm = algorithm
        self.time_step = time_step
        self.drift_tolerance = drift_tolerance

    async def get_enrollment(self, identity_id: typing.Any) -> TOTPEnrollment | None:
        """
        Get the TOTP enrollment for a given identity, returning only enabled enrollments.

        This method returns None for both non-existent enrollments and disabled enrollments.
        Use `get_by_identity_id` if you need to access disabled enrollments
        (e.g., during the enable flow).

        Args:
            identity_id: The ID of the identity to get the TOTP enrollment for.

        Returns:
            The enabled TOTP enrollment for the identity, or None if no enrollment exists
            or the enrollment is disabled.
        """
        enrollment = await self.get_by_identity_id(identity_id)
        if enrollment is None or not enrollment.enabled:
            return None
        return enrollment

    async def enroll(self, identity_id: typing.Any) -> TOTPEnrollment:
        """
        Enroll a new TOTP factor for a given identity.

        It starts in a disabled state, and must be enabled by verifying a first
        code with the `enable` method.

        Args:
            identity_id: The ID of the identity to enroll the factor for.

        Returns:
            The enrolled TOTP factor.

        Raises:
            AlreadyEnrolledTOTPException: If the identity already has a TOTP enrollment.
        """
        logger.debug("TOTP enroll attempted", extra={"identity_id": identity_id})
        existing = await self.get_by_identity_id(identity_id)
        if existing is not None:
            if existing.enabled:
                raise AlreadyEnrolledTOTPException()
            # Delete disabled enrollment to allow re-enrollment
            logger.debug(
                "TOTP re-enroll: deleting disabled enrollment",
                extra={"identity_id": identity_id},
            )
            await self.delete(existing)

        secret = secrets.token_bytes(20)  # 160-bit secret key
        totp = TOTPEnrollment(
            id=None,
            identity_id=identity_id,
            enabled=False,
            secret=base64.b32encode(secret).decode("ascii"),
            algorithm=self.algorithm,
            code_length=self.code_length,
            time_step=self.time_step,
            last_verified_time_step=None,
        )
        totp.id = await self.insert(totp)
        logger.info(
            "TOTP enrollment created",
            extra={
                "identity_id": identity_id,
                "code_length": self.code_length,
                "algorithm": self.algorithm,
            },
        )
        return totp

    async def enable(self, identity_id: typing.Any, code: str) -> TOTPEnrollment:
        """
        Enable a TOTP factor by verifying a provided OTP code against the expected value.

        On success, the TOTP factor is marked as enabled and updated in the persistent store.

        Args:
            identity_id: The ID of the identity to enable the TOTP factor for.
            code: The OTP code provided by the user.

        Returns:
            The updated TOTP enrollment.

        Raises:
            NotEnrolledTOTPException: If the identity has no TOTP enrollment.
            AlreadyEnabledTOTPException: If the TOTP factor is already enabled.
            InvalidTOTPCodeException: If the provided code is invalid.
        """
        logger.debug("TOTP enable attempted", extra={"identity_id": identity_id})
        totp = await self.get_by_identity_id(identity_id)
        if totp is None:
            logger.warning(
                "TOTP enable failed: not enrolled",
                extra={"identity_id": identity_id},
            )
            raise NotEnrolledTOTPException()
        if totp.enabled:
            logger.warning(
                "TOTP enable failed: already enabled",
                extra={"identity_id": identity_id},
            )
            raise AlreadyEnabledTOTPException()

        try:
            totp = self._verify(totp, code)
        except InvalidTOTPCodeException:
            logger.warning(
                "TOTP enable failed: invalid code",
                extra={"identity_id": identity_id},
            )
            raise

        totp.enabled = True
        await self.update(totp)
        logger.info("TOTP enabled", extra={"identity_id": identity_id})
        return totp

    async def verify(self, identity_id: typing.Any, code: str) -> TOTPEnrollment:
        """
        Verify a provided OTP code against the expected value for the given TOTP factor.

        Args:
            identity_id: The ID of the identity to verify the TOTP code for.
            code: The OTP code provided by the user.

        Returns:
            The updated TOTP enrollment.

        Raises:
            NotEnrolledTOTPException: If the identity has no TOTP enrollment.
            NotEnabledTOTPException: If the TOTP factor is not enabled.
            InvalidTOTPCodeException: If the provided code is invalid or has already been used.
        """
        logger.debug("TOTP verification attempted", extra={"identity_id": identity_id})
        totp = await self.get_by_identity_id(identity_id)
        if totp is None:
            logger.warning(
                "TOTP verify failed: not enrolled",
                extra={"identity_id": identity_id},
            )
            raise NotEnrolledTOTPException()
        if not totp.enabled:
            logger.warning(
                "TOTP verify failed: not enabled",
                extra={"identity_id": identity_id},
            )
            raise NotEnabledTOTPException()

        try:
            totp = self._verify(totp, code)
        except InvalidTOTPCodeException:
            logger.warning(
                "TOTP verify failed: invalid code",
                extra={"identity_id": identity_id},
            )
            raise

        await self.update(totp)
        logger.info("TOTP verification successful", extra={"identity_id": identity_id})
        return totp

    def _verify(self, totp: TOTPEnrollment, code: str) -> TOTPEnrollment:
        encoded_code = code.encode("ascii")
        current_time = int(time.time())
        drift = -self.drift_tolerance

        while True:
            try:
                # Calculate the actual Unix time for this drift step
                check_time = current_time + drift * totp.time_step
                # Calculate the time step for this check
                check_time_step = check_time // totp.time_step

                # Replay protection: reject if this time step has already been verified
                if (
                    totp.last_verified_time_step is not None
                    and check_time_step <= totp.last_verified_time_step
                ):
                    drift += 1
                    continue

                totp._impl.verify(encoded_code, check_time)
            except InvalidToken as e:
                if drift > self.drift_tolerance:
                    raise InvalidTOTPCodeException() from e
                drift += 1
            else:
                # Update last verified time step
                totp.last_verified_time_step = check_time_step
                return totp

    @abc.abstractmethod
    async def get_by_identity_id(
        self, identity_id: typing.Any
    ) -> TOTPEnrollment | None:
        """
        Get the raw TOTP enrollment for a given identity, regardless of its enabled state.

        This method is the primary data access point for implementers. It should retrieve
        the enrollment record from persistent storage without any filtering based on
        the enabled state.

        The `get_enrollment` method uses this to provide a filtered view that excludes
        disabled enrollments.

        Args:
            identity_id: The ID of the identity to get the TOTP enrollment for.

        Returns:
            The TOTP enrollment for the identity, or None if no enrollment exists.
            This may return a disabled enrollment.
        """
        ...

    @abc.abstractmethod
    async def insert(self, totp: TOTPEnrollment) -> typing.Any:
        """Insert a TOTP factor into a persistent store."""
        ...

    @abc.abstractmethod
    async def update(self, totp: TOTPEnrollment) -> None:
        """Update a TOTP factor in the persistent store."""
        ...

    @abc.abstractmethod
    async def delete(self, totp: TOTPEnrollment) -> None:
        """Delete a TOTP factor from the persistent store."""
        ...
