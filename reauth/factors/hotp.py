import abc
import base64
import dataclasses
import functools
import secrets
import typing
import unicodedata

from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.twofactor import InvalidToken
from cryptography.hazmat.primitives.twofactor.hotp import HOTP as CryptoHOTP

from reauth.amr import AuthenticationMethodReference
from reauth.exceptions import ReauthException
from reauth.factors.base import FactorBase
from reauth.logging import get_logger

logger = get_logger(__name__)

type HOTPAlgorithm = typing.Literal["sha1"]


def _get_algorithm(algorithm: HOTPAlgorithm) -> SHA1:
    match algorithm:
        case "sha1":
            return SHA1()


@dataclasses.dataclass
class HOTPEnrollment:
    id: typing.Any | None
    identity_id: typing.Any
    enabled: bool
    secret: str
    algorithm: HOTPAlgorithm
    code_length: int
    counter: int

    @functools.cached_property
    def _impl(self) -> CryptoHOTP:
        try:
            key = base64.b32decode(self.secret)
        except ValueError as exc:
            message = "Invalid Base32 HOTP secret"
            raise ValueError(message) from exc
        return CryptoHOTP(
            key=key,
            length=self.code_length,
            algorithm=_get_algorithm(self.algorithm),
        )

    def get_provisioning_uri(
        self, account_name: str, issuer_name: str | None = None
    ) -> str:
        """
        Get the provisioning URI for this HOTP factor.

        Args:
            account_name: The name of the account (e.g., email or username).
            issuer_name: The name of the issuer (e.g., your service name).

        Returns:
            The provisioning URI that can be used to generate a QR code for enrollment in an authenticator app.
        """
        return self._impl.get_provisioning_uri(account_name, self.counter, issuer_name)


class HOTPException(ReauthException):
    """Base exception for HOTP errors."""


class AlreadyEnabledHOTPException(HOTPException):
    """Raised when trying to enable an already enabled HOTP factor."""


class NotEnabledHOTPException(HOTPException):
    """Raised when trying to verify an HOTP factor that is not enabled."""


class InvalidHOTPCodeException(HOTPException):
    """Raised when an HOTP code is invalid."""


class AlreadyEnrolledHOTPException(HOTPException):
    """Raised when trying to enroll an identity that already has an HOTP enrollment."""


class NotEnrolledHOTPException(HOTPException):
    """Raised when trying to enable or verify an HOTP factor for an identity with no enrollment."""


class HOTPFactor(FactorBase[HOTPEnrollment], abc.ABC):
    AMR: typing.ClassVar[AuthenticationMethodReference] = (
        AuthenticationMethodReference.OTP
    )

    def __init__(
        self,
        *,
        code_length: int = 6,
        algorithm: HOTPAlgorithm = "sha1",
        look_ahead: int = 5,
        identifier: str = "hotp",
        step: int = 1,
        advance_by: int = 1,
    ) -> None:
        super().__init__(identifier=identifier, step=step, advance_by=advance_by)
        self.code_length = code_length
        self.algorithm: HOTPAlgorithm = algorithm
        self.look_ahead = look_ahead

    async def get_enrollment(self, identity_id: typing.Any) -> HOTPEnrollment | None:
        """
        Get the HOTP enrollment for a given identity, returning only enabled enrollments.

        This method returns None for both non-existent enrollments and disabled enrollments.
        Use `get_by_identity_id` if you need to access disabled enrollments
        (e.g., during the enable flow).

        Args:
            identity_id: The ID of the identity to get the HOTP enrollment for.

        Returns:
            The enabled HOTP enrollment for the identity, or None if no enrollment exists
            or the enrollment is disabled.
        """
        enrollment = await self.get_by_identity_id(identity_id)
        if enrollment is None or not enrollment.enabled:
            return None
        return enrollment

    async def enroll(self, identity_id: typing.Any) -> HOTPEnrollment:
        """
        Enroll a new HOTP factor for a given identity.

        It starts in a disabled state, and must be enabled by verifying a first
        code with the `enable` method.

        Args:
            identity_id: The ID of the identity to enroll the factor for.

        Returns:
            The enrolled HOTP factor.

        Raises:
            AlreadyEnrolledHOTPException: If the identity already has an HOTP enrollment.
        """
        logger.debug("HOTP enroll attempted", extra={"identity_id": identity_id})
        existing = await self.get_by_identity_id(identity_id)
        if existing is not None:
            if existing.enabled:
                raise AlreadyEnrolledHOTPException()
            # Delete disabled enrollment to allow re-enrollment
            logger.debug(
                "HOTP re-enroll: deleting disabled enrollment",
                extra={"identity_id": identity_id},
            )
            await self.delete(existing)

        secret = secrets.token_bytes(20)  # 160-bit secret key
        hotp = HOTPEnrollment(
            id=None,
            enabled=False,
            secret=base64.b32encode(secret).decode("ascii"),
            algorithm=self.algorithm,
            code_length=self.code_length,
            counter=0,
            identity_id=identity_id,
        )
        hotp.id = await self.insert(hotp)
        logger.info(
            "HOTP enrollment created",
            extra={
                "identity_id": identity_id,
                "code_length": self.code_length,
                "algorithm": self.algorithm,
            },
        )
        return hotp

    async def enable(self, identity_id: typing.Any, code: str) -> HOTPEnrollment:
        """
        Enable an HOTP factor by verifying a provided OTP code against the expected value.

        On success, the HOTP factor is marked as enabled and updated in the persistent store.

        Args:
            identity_id: The ID of the identity to enable the HOTP factor for.
            code: The OTP code provided by the user.

        Returns:
            The updated HOTP enrollment.

        Raises:
            NotEnrolledHOTPException: If the identity has no HOTP enrollment.
            AlreadyEnabledHOTPException: If the HOTP factor is already enabled.
            InvalidHOTPCodeException: If the provided code is invalid.
        """
        logger.debug("HOTP enable attempted", extra={"identity_id": identity_id})
        hotp = await self.get_by_identity_id(identity_id)
        if hotp is None:
            logger.warning(
                "HOTP enable failed: not enrolled",
                extra={"identity_id": identity_id},
            )
            raise NotEnrolledHOTPException()
        if hotp.enabled:
            logger.warning(
                "HOTP enable failed: already enabled",
                extra={"identity_id": identity_id},
            )
            raise AlreadyEnabledHOTPException()

        try:
            hotp = self._verify(hotp, code)
        except InvalidHOTPCodeException:
            logger.warning(
                "HOTP enable failed: invalid code",
                extra={"identity_id": identity_id},
            )
            raise

        hotp.enabled = True
        await self.update(hotp)
        logger.info("HOTP enabled", extra={"identity_id": identity_id})
        return hotp

    async def verify(self, identity_id: typing.Any, code: str) -> HOTPEnrollment:
        """
        Verify a provided OTP code against the expected value for the given HOTP factor.

        On success, the counter is incremented and the HOTP factor is updated in the persistent store.

        Args:
            identity_id: The ID of the identity to verify the HOTP code for.
            code: The OTP code provided by the user.

        Returns:
            The updated HOTP enrollment.

        Raises:
            NotEnrolledHOTPException: If the identity has no HOTP enrollment.
            NotEnabledHOTPException: If the HOTP factor is not enabled.
            InvalidHOTPCodeException: If the provided code is invalid.
        """
        logger.debug("HOTP verification attempted", extra={"identity_id": identity_id})
        hotp = await self.get_by_identity_id(identity_id)
        if hotp is None:
            logger.warning(
                "HOTP verify failed: not enrolled",
                extra={"identity_id": identity_id},
            )
            raise NotEnrolledHOTPException()
        if not hotp.enabled:
            logger.warning(
                "HOTP verify failed: not enabled",
                extra={"identity_id": identity_id},
            )
            raise NotEnabledHOTPException()

        try:
            hotp = self._verify(hotp, code)
        except InvalidHOTPCodeException:
            logger.warning(
                "HOTP verify failed: invalid code",
                extra={"identity_id": identity_id},
            )
            raise

        await self.update(hotp)
        logger.info("HOTP verification successful", extra={"identity_id": identity_id})
        return hotp

    def _verify(self, hotp: HOTPEnrollment, code: str) -> HOTPEnrollment:
        code = unicodedata.normalize("NFKC", code)
        if len(code) != hotp.code_length or not code.isascii() or not code.isdigit():
            raise InvalidHOTPCodeException()
        encoded_code = code.encode("ascii")
        counter = hotp.counter

        while True:
            try:
                hotp._impl.verify(encoded_code, counter)
                break
            except InvalidToken as e:
                if counter - hotp.counter >= self.look_ahead:
                    raise InvalidHOTPCodeException() from e
                counter += 1

        hotp.counter = counter + 1
        return hotp

    @abc.abstractmethod
    async def get_by_identity_id(
        self, identity_id: typing.Any
    ) -> HOTPEnrollment | None:
        """
        Get the raw HOTP enrollment for a given identity, regardless of its enabled state.

        Args:
            identity_id: The ID of the identity to get the HOTP enrollment for.

        Returns:
            The HOTP enrollment for the identity, or None if no enrollment exists.
            This may return a disabled enrollment.

        Abstract: Implementation contract
            Scope the lookup to the identity and configured factor. Include disabled
            enrollments. Acquire protection before reading and retain it until the
            caller's transaction ends, protecting the counter and enabled state from
            competing mutations. Do not commit or roll back. Acquire multiple locks
            in a consistent order. An absent row is not protected by a row lock.
        """
        ...

    @abc.abstractmethod
    async def insert(self, hotp: HOTPEnrollment) -> typing.Any:
        """
        Insert an HOTP factor into a persistent store.

        Args:
            hotp: The HOTP factor to insert.

        Returns:
            The ID of the inserted HOTP factor.

        Abstract: Implementation contract
            Persist the supplied enrollment and return its record ID. Enforce
            uniqueness for the identity and configured factor, including concurrent
            first enrollments. Participate in the caller's transaction without
            committing or rolling it back.
        """
        ...

    @abc.abstractmethod
    async def update(self, hotp: HOTPEnrollment) -> None:
        """
        Update an HOTP factor in the persistent store.

        Args:
            hotp: The HOTP factor to update.

        Abstract: Implementation contract
            Persist the supplied enrollment by ID, including its counter and enabled
            state, in the transaction that protected the lookup. Do not allow a stale
            write to undo a counter advance or a concurrent enrollment change. Leave
            commit and rollback to the caller.
        """
        ...

    @abc.abstractmethod
    async def delete(self, hotp: HOTPEnrollment) -> None:
        """
        Delete an HOTP factor from the persistent store.

        Args:
            hotp: The HOTP factor to delete.

        Abstract: Implementation contract
            Delete the supplied enrollment by ID in the transaction that protects
            the record. Retain that protection and leave commit and rollback to the
            caller.
        """
        ...
