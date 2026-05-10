import abc
import dataclasses
import datetime
import typing
from typing import ClassVar

from reauth.exceptions import ReauthException

from ..amr import AuthenticationMethodReference
from ..crypto import generate_code_hash_pair, get_token_hash
from ..timestamp import get_current_timestamp


@dataclasses.dataclass
class EmailOTP:
    id: typing.Any | None
    code_hash: str
    expires_at: int
    identity_id: typing.Any
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

    pass


class InvalidOTPException(EmailOTPException):
    """Raised when an OTP code is invalid."""

    pass


class ExpiredOTPException(EmailOTPException):
    """Raised when an OTP code has expired."""

    pass


class EmailOTPFactor(abc.ABC):
    AMR: ClassVar[AuthenticationMethodReference] = AuthenticationMethodReference.EMAIL

    def __init__(
        self,
        *,
        hash_secret: str,
        code_length: int = 6,
        lifetime: datetime.timedelta = datetime.timedelta(minutes=10),
    ) -> None:
        self.hash_secret = hash_secret
        self.code_length = code_length
        self.lifetime = lifetime

    async def create(
        self, identity_id: typing.Any, authentication_session_id: typing.Any
    ) -> tuple[str, EmailOTP]:
        """
        Create a new OTP for the given identity.

        If an existing OTP for the same authentication session exists,
        it's deleted and replaced with the new one.

        Args:
            identity_id: The ID of the identity to create the OTP for.
            authentication_session_id: The ID of the authentication session this OTP is associated with.

        Returns:
            A tuple of (OTP code, EmailOTP instance).
        """
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
        )
        email_otp.id = await self.insert(email_otp)

        return code, email_otp

    async def consume(self, code: str, authentication_session_id: object) -> None:
        """
        Consume an OTP code, deleting it from the persistent store if valid.

        Args:
            code: The OTP code to consume.
            authentication_session_id: The ID of the authentication session this OTP is associated with.

        Returns:
            The corresponding EmailOTP instance.

        Raises:
            InvalidOTPException: If the code is invalid or does not correspond to any OTP.
            ExpiredOTPException: If the OTP has expired.
        """
        code_hash = get_token_hash(code, secret=self.hash_secret)
        email_otp = await self.get_by_code_hash_and_authentication_session_id(
            code_hash, authentication_session_id
        )
        if email_otp is None:
            raise InvalidOTPException()
        if email_otp.is_expired():
            raise ExpiredOTPException()
        await self.delete(email_otp)

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
    async def update(self, email_otp: EmailOTP) -> None:
        """
        Update an EmailOTP instance in the persistent store.

        Implementers should implement this method.

        Args:
            email_otp: The EmailOTP instance to update.
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
