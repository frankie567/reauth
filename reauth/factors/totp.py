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
class TOTP:
    id: typing.Any | None
    secret: str
    algorithm: TOTPAlgorithm
    code_length: int
    time_step: int
    identity_id: typing.Any
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


class TOTPFactor(abc.ABC):
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
    ) -> None:
        self.code_length = code_length
        self.algorithm: TOTPAlgorithm = algorithm
        self.time_step = time_step
        self.drift_tolerance = drift_tolerance

    async def enroll(self, identity_id: typing.Any) -> TOTP:
        """
        Enroll a new TOTP factor for a given identity.

        Args:
            identity_id: The ID of the identity to enroll the factor for.

        Returns:
            The enrolled TOTP factor.
        """
        secret = secrets.token_bytes(20)  # 160-bit secret key
        totp = TOTP(
            id=None,
            secret=base64.b32encode(secret).decode("ascii"),
            algorithm=self.algorithm,
            code_length=self.code_length,
            time_step=self.time_step,
            identity_id=identity_id,
            last_verified_time_step=None,
        )
        totp.id = await self.insert(totp)
        return totp

    async def verify(self, totp: TOTP, code: str) -> None:
        """
        Verify a provided OTP code against the expected value for the given TOTP factor.

        Args:
            totp: The TOTP factor to verify against.
            code: The OTP code provided by the user.

        Raises:
            InvalidTOTPCodeException: If the provided code is invalid or has already been used.
        """
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
                # Update last verified time step and persist
                totp.last_verified_time_step = check_time_step
                await self.update(totp)
                return

    @abc.abstractmethod
    async def insert(self, totp: TOTP) -> typing.Any:
        """Insert a TOTP factor into a persistent store."""
        ...

    @abc.abstractmethod
    async def update(self, totp: TOTP) -> None:
        """Update a TOTP factor in the persistent store."""
        ...
