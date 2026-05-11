import abc
import base64
import dataclasses
import functools
import secrets
import typing

from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.twofactor import InvalidToken
from cryptography.hazmat.primitives.twofactor.hotp import HOTP as CryptoHOTP

from reauth.exceptions import ReauthException

from ..amr import AuthenticationMethodReference
from .base import FactorBase

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
        return CryptoHOTP(
            key=base64.b32decode(self.secret.encode("ascii")),
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

    pass


class AlreadyEnabledHOTPException(HOTPException):
    """Raised when trying to enable an already enabled HOTP factor."""

    pass


class NotEnabledHOTPException(HOTPException):
    """Raised when trying to verify an HOTP factor that is not enabled."""

    pass


class InvalidHOTPCodeException(HOTPException):
    """Raised when an HOTP code is invalid."""

    pass


class HOTPFactor(FactorBase, abc.ABC):
    AMR: typing.ClassVar[AuthenticationMethodReference] = (
        AuthenticationMethodReference.OTP
    )

    def __init__(
        self,
        *,
        code_length: int = 6,
        algorithm: HOTPAlgorithm = "sha1",
        look_ahead: int = 5,
        min_prior_factors: int = 1,
    ) -> None:
        super().__init__(min_prior_factors=min_prior_factors)
        self.code_length = code_length
        self.algorithm: HOTPAlgorithm = algorithm
        self.look_ahead = look_ahead

    async def enroll(self, identity_id: typing.Any) -> HOTPEnrollment:
        """
        Enroll a new HOTP factor for a given identity.

        It starts in a disabled state, and must be enabled by verifying a first
        code with the `enable` method.

        Args:
            identity_id: The ID of the identity to enroll the factor for.

        Returns:
            The enrolled HOTP factor.
        """
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
        return hotp

    async def enable(self, hotp: HOTPEnrollment, code: str) -> None:
        """
        Enable an HOTP factor by verifying a provided OTP code against the expected value.

        On success, the HOTP factor is marked as enabled and updated in the persistent store.

        Args:
            hotp: The HOTP factor to enable.
            code: The OTP code provided by the user.

        Raises:
            AlreadyEnabledHOTPException: If the HOTP factor is already enabled.
            InvalidHOTPCodeException: If the provided code is invalid.
        """
        if hotp.enabled:
            raise AlreadyEnabledHOTPException()

        hotp = self._verify(hotp, code)
        hotp.enabled = True
        await self.update(hotp)

    async def verify(self, hotp: HOTPEnrollment, code: str) -> None:
        """
        Verify a provided OTP code against the expected value for the given HOTP factor.

        On success, the counter is incremented and the HOTP factor is updated in the persistent store.

        Args:
            hotp: The HOTP factor to verify against.
            code: The OTP code provided by the user.

        Raises:
            NotEnabledHOTPException: If the HOTP factor is not enabled.
            InvalidHOTPCodeException: If the provided code is invalid.
        """
        if not hotp.enabled:
            raise NotEnabledHOTPException()

        hotp = self._verify(hotp, code)
        await self.update(hotp)

    def _verify(self, hotp: HOTPEnrollment, code: str) -> HOTPEnrollment:
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
    async def insert(self, hotp: HOTPEnrollment) -> typing.Any:
        """
        Insert an HOTP factor into a persistent store.

        Implementers should implement this method.

        Args:
            hotp: The HOTP factor to insert.

        Returns:
            The ID of the inserted HOTP factor.
        """
        ...

    @abc.abstractmethod
    async def update(self, hotp: HOTPEnrollment) -> None:
        """
        Update an HOTP factor in the persistent store.

        Implementers should implement this method.

        Args:
            hotp: The HOTP factor to update.
        """
        ...
