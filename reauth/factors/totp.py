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

from reauth.exceptions import ReauthException

from ..amr import AuthenticationMethodReference
from .base import FactorBase

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

    pass


class InvalidTOTPCodeException(TOTPException):
    """Raised when a TOTP code is invalid."""

    pass


class AlreadyEnabledTOTPException(TOTPException):
    """Raised when trying to enable an already enabled TOTP factor."""

    pass


class NotEnabledTOTPException(TOTPException):
    """Raised when trying to verify a TOTP factor that is not enabled."""

    pass


class TOTPFactor(FactorBase, abc.ABC):
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
        min_prior_factors: int = 1,
    ) -> None:
        super().__init__(min_prior_factors=min_prior_factors)
        self.code_length = code_length
        self.algorithm: TOTPAlgorithm = algorithm
        self.time_step = time_step
        self.drift_tolerance = drift_tolerance

    async def enroll(self, identity_id: typing.Any) -> TOTPEnrollment:
        """
        Enroll a new TOTP factor for a given identity.

        It starts in a disabled state, and must be enabled by verifying a first
        code with the `enable` method.

        Args:
            identity_id: The ID of the identity to enroll the factor for.

        Returns:
            The enrolled TOTP factor.
        """
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
        return totp

    async def enable(self, totp: TOTPEnrollment, code: str) -> None:
        """
        Enable a TOTP factor by verifying a provided OTP code against the expected value.

        On success, the TOTP factor is marked as enabled and updated in the persistent store.

        Args:
            totp: The TOTP factor to enable.
            code: The OTP code provided by the user.

        Raises:
            AlreadyEnabledTOTPException: If the TOTP factor is already enabled.
            InvalidTOTPCodeException: If the provided code is invalid.
        """
        if totp.enabled:
            raise AlreadyEnabledTOTPException()

        totp = self._verify(totp, code)
        totp.enabled = True
        await self.update(totp)

    async def verify(self, totp: TOTPEnrollment, code: str) -> None:
        """
        Verify a provided OTP code against the expected value for the given TOTP factor.

        Args:
            totp: The TOTP factor to verify against.
            code: The OTP code provided by the user.

        Raises:
            NotEnabledTOTPException: If the TOTP factor is not enabled.
            InvalidTOTPCodeException: If the provided code is invalid or has already been used.
        """
        if not totp.enabled:
            raise NotEnabledTOTPException()

        totp = self._verify(totp, code)
        await self.update(totp)

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
    async def insert(self, totp: TOTPEnrollment) -> typing.Any:
        """Insert a TOTP factor into a persistent store."""
        ...

    @abc.abstractmethod
    async def update(self, totp: TOTPEnrollment) -> None:
        """Update a TOTP factor in the persistent store."""
        ...
