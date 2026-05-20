import abc
import dataclasses
import datetime
import hashlib
import typing

from reauth.amr import AuthenticationMethodReference
from reauth.crypto import generate_code_hash_pair, get_token_hash
from reauth.exceptions import ReauthException
from reauth.factors.base import FactorBase
from reauth.logging import get_logger
from reauth.timestamp import get_current_timestamp

logger = get_logger(__name__)


def _hash_email(email: str) -> str:
    """Hash email for logging correlation without exposing PII.

    Args:
        email: The email address to hash.

    Returns:
        The SHA-256 hash of the email as a hexadecimal string.
    """
    return hashlib.sha256(email.encode()).hexdigest()


@dataclasses.dataclass
class EmailOTPEnrollment:
    id: typing.Any | None
    identity_id: typing.Any
    email: str


@dataclasses.dataclass
class EmailOTP:
    id: typing.Any | None
    identity_id: typing.Any | None
    email: str
    code_hash: str
    expires_at: int
    authentication_session_id: typing.Any

    def is_expired(self) -> bool:
        """
        Check if the OTP has expired.

        Returns:
            True if the OTP has expired, False otherwise.
        """
        return get_current_timestamp() >= self.expires_at


class EmailOTPException(ReauthException):
    """Base exception for email OTP errors."""


class InvalidOTPException(EmailOTPException):
    """Raised when an OTP code is invalid."""


class ExpiredOTPException(EmailOTPException):
    """Raised when an OTP code has expired."""


class EmailOTPFactor(FactorBase[EmailOTPEnrollment], abc.ABC):
    AMR: typing.ClassVar[AuthenticationMethodReference] = (
        AuthenticationMethodReference.EMAIL
    )

    def __init__(
        self,
        *,
        hash_secret: str,
        code_length: int = 6,
        lifetime: datetime.timedelta = datetime.timedelta(minutes=10),
        identifier: str = "email_otp",
        step: int = 0,
    ) -> None:
        super().__init__(identifier=identifier, step=step)
        self.hash_secret = hash_secret
        self.code_length = code_length
        self.lifetime = lifetime

    async def create(
        self,
        email: str,
        authentication_session_id: typing.Any,
        identity_id: typing.Any | None = None,
    ) -> tuple[str, EmailOTP]:
        """
        Create a new OTP for the given identity.

        If an existing OTP for the same authentication session exists,
        it's deleted and replaced with the new one.

        Args:
            email: The email address this OTP is sent to.
            authentication_session_id: The ID of the authentication session this OTP is associated with.
            identity_id: Optional ID of the identity to create the OTP for. Can be None for signup flows.

        Returns:
            A tuple of (OTP code, EmailOTP instance).
        """
        logger.debug(
            "Email OTP send attempted", extra={"email_hash": _hash_email(email)}
        )
        await self.delete_by_authentication_session_id(authentication_session_id)

        code, code_hash = generate_code_hash_pair(
            secret=self.hash_secret, length=self.code_length
        )
        email_otp = EmailOTP(
            id=None,
            code_hash=code_hash,
            expires_at=get_current_timestamp() + int(self.lifetime.total_seconds()),
            identity_id=identity_id,
            authentication_session_id=authentication_session_id,
            email=email,
        )
        email_otp.id = await self.insert(email_otp)

        logger.info(
            "Email OTP created",
            extra={
                "identity_id": identity_id,
                "authentication_session_id": authentication_session_id,
                "email_hash": _hash_email(email),
            },
        )
        return code, email_otp

    async def consume(
        self, code: str, authentication_session_id: typing.Any
    ) -> tuple[typing.Any | None, str]:
        """
        Consume an OTP code, deleting it from the persistent store if valid.

        Args:
            code: The OTP code to consume.
            authentication_session_id: The ID of the authentication session this OTP is associated with.

        Returns:
            A tuple of (identity_id, email). identity_id is None for new users (signup flow).
            For signup flows where identity_id is None, the application MUST create an
            identity and EmailOTPEnrollment after successful OTP verification.

        Raises:
            InvalidOTPException: If the code is invalid or does not correspond to any OTP.
            ExpiredOTPException: If the OTP has expired.
        """
        logger.debug(
            "Email OTP consumption attempted",
            extra={"authentication_session_id": authentication_session_id},
        )
        code_hash = get_token_hash(code, secret=self.hash_secret)
        email_otp = await self.get_by_code_hash_and_authentication_session_id(
            code_hash, authentication_session_id
        )
        if email_otp is None:
            logger.warning(
                "Email OTP consume failed: invalid",
                extra={"authentication_session_id": authentication_session_id},
            )
            raise InvalidOTPException()
        if email_otp.is_expired():
            logger.warning(
                "Email OTP consume failed: expired",
                extra={"authentication_session_id": authentication_session_id},
            )
            raise ExpiredOTPException()
        await self.delete(email_otp)
        logger.info(
            "Email OTP consumed",
            extra={
                "authentication_session_id": authentication_session_id,
                "identity_id": email_otp.identity_id,
                "email_hash": _hash_email(email_otp.email),
            },
        )
        return email_otp.identity_id, email_otp.email

    @abc.abstractmethod
    async def insert(self, email_otp: EmailOTP) -> typing.Any:
        """
        Insert an EmailOTP instance into a persistent store.

        Implementers should implement this method.

        Args:
            email_otp: The EmailOTP instance to insert.

        Returns:
            The ID of the inserted EmailOTP.
        """
        ...

    @abc.abstractmethod
    async def get_by_code_hash_and_authentication_session_id(
        self, code_hash: str, authentication_session_id: typing.Any
    ) -> EmailOTP | None:
        """
        Retrieve an EmailOTP instance by its code hash from the persistent store.

        Implementers should implement this method.

        Args:
            code_hash: The hash of the OTP code to retrieve.
            authentication_session_id: The ID of the authentication session this OTP is associated with.

        Returns:
            The corresponding EmailOTP instance, or None if not found.
        """
        ...

    @abc.abstractmethod
    async def delete(self, email_otp: EmailOTP) -> None:
        """
        Delete an EmailOTP instance from the persistent store.

        Implementers should implement this method.

        Args:
            email_otp: The EmailOTP instance to delete.
        """
        ...

    @abc.abstractmethod
    async def delete_by_authentication_session_id(
        self, authentication_session_id: typing.Any
    ) -> None:
        """
        Delete all EmailOTP instances associated with a given authentication session ID.

        Implementers should implement this method.

        Args:
            authentication_session_id: The ID of the authentication session to delete OTPs for.
        """
        ...
