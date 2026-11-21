import abc
import dataclasses
import datetime
import typing

from reauth.amr import AuthenticationMethodReference
from reauth.exceptions import ReauthException
from reauth.factors.base import SingleEnrollmentFactorBase
from reauth.factors.password.hashing import (
    PasswordHash,
    PasswordHashException,
    PasswordHashGenerationException,
    PasswordHashVerificationException,
)
from reauth.logging import get_logger
from reauth.timestamp import get_current_timestamp
from reauth.tokens import InvalidTokenException, TokenProvider

logger = get_logger(__name__)


@dataclasses.dataclass
class PasswordEnrollment:
    id: typing.Any | None
    identity_id: typing.Any
    password_hash: str | None
    reset_token_identifier: str | None = None
    reset_token_verifier: str | None = None
    reset_token_expires_at: int | None = None


class PasswordException(ReauthException):
    """Base exception for password factor errors."""


class IdentityNotFoundException(PasswordException):
    """The identity does not exist."""


class AlreadyEnrolledPasswordException(PasswordException):
    """The identity already has a password."""


class NotEnrolledPasswordException(PasswordException):
    """The identity has no password enrollment."""


class InvalidPasswordException(PasswordException):
    """The password does not match."""


class InvalidPasswordResetTokenException(PasswordException):
    """The reset token is invalid, expired, or already consumed."""


class PasswordFactor(SingleEnrollmentFactorBase[PasswordEnrollment], abc.ABC):
    AMR: typing.ClassVar[AuthenticationMethodReference] = (
        AuthenticationMethodReference.PWD
    )

    def __init__(
        self,
        *,
        token_provider: TokenProvider,
        password_hash: PasswordHash | None = None,
        reset_lifetime: datetime.timedelta = datetime.timedelta(minutes=30),
        identifier: str = "password",
        step: int = 0,
        advance_by: int = 1,
    ) -> None:
        """Initialize the password factor.

        Args:
            token_provider: Reset token generation, parsing, and verification.
            password_hash: Synchronous hashing backend. Defaults to PwdlibPasswordHash,
                which requires the password extra.
            reset_lifetime: Reset token lifetime. Defaults to 30 minutes.
            identifier: Unique identifier for this configured factor.
            step: Authentication step at which this factor is available.
            advance_by: Number of authentication steps advanced on success.

        Raises:
            ValueError: If reset_lifetime is less than one second or advance_by
                is less than one.
        """
        super().__init__(identifier=identifier, step=step, advance_by=advance_by)
        if reset_lifetime.total_seconds() < 1:
            message = "reset_lifetime must be at least one second"
            raise ValueError(message)
        if password_hash is None:
            from reauth.factors.password.pwdlib import PwdlibPasswordHash

            password_hash = PwdlibPasswordHash()
        self.password_hash = password_hash
        self.token_provider = token_provider
        self.reset_lifetime = reset_lifetime

    async def get_enrollment(
        self, identity_id: typing.Any
    ) -> PasswordEnrollment | None:
        """Return the password enrollment, or None when no password is configured.

        Args:
            identity_id: The ID of the identity whose password state is accessed.

        Returns:
            The configured enrollment, or None.
        """
        enrollment = await self.get_by_identity_id(identity_id)
        return (
            enrollment
            if enrollment is not None and enrollment.password_hash is not None
            else None
        )

    async def enroll(
        self, identity_id: typing.Any, password: str
    ) -> PasswordEnrollment:
        """Set the first password on an existing identity.

        Args:
            identity_id: The ID of the identity whose password state is accessed.
            password: The plaintext password.

        Returns:
            The new enrollment.

        Raises:
            IdentityNotFoundException: The identity does not exist.
            AlreadyEnrolledPasswordException: A password is already configured.
        """
        logger.debug(
            "Password enrollment attempted", extra={"identity_id": identity_id}
        )
        enrollment = await self.get_by_identity_id(identity_id)
        if enrollment is None:
            logger.warning(
                "Password enrollment failed: identity missing",
                extra={"identity_id": identity_id},
            )
            raise IdentityNotFoundException()
        if enrollment.password_hash is not None:
            logger.warning(
                "Password enrollment failed: already enrolled",
                extra={"identity_id": identity_id},
            )
            raise AlreadyEnrolledPasswordException()
        enrollment = await self._set_password(enrollment, password)
        logger.info("Password enrolled", extra={"identity_id": identity_id})
        return enrollment

    async def verify(
        self, identity_id: typing.Any, password: str
    ) -> PasswordEnrollment:
        """Verify the password and persist any hash upgrade.

        Call this method even when an account lookup fails. If no password
        enrollment is available, the configured backend hashes the supplied
        password and discards the result to reduce timing differences.

        Args:
            identity_id: The identity ID, or None if the account lookup failed.
                None skips the enrollment lookup.
            password: The plaintext password.

        Returns:
            The verified enrollment.

        Raises:
            NotEnrolledPasswordException: The identity is missing or has no password.
            InvalidPasswordException: The password does not match.
        """
        logger.debug(
            "Password verification attempted", extra={"identity_id": identity_id}
        )
        enrollment = (
            await self.get_enrollment(identity_id) if identity_id is not None else None
        )
        if enrollment is None:
            self.password_hash.hash(password)
            logger.warning(
                "Password verification failed: not enrolled",
                extra={"identity_id": identity_id},
            )
            raise NotEnrolledPasswordException()
        assert enrollment.password_hash is not None
        valid, replacement = self.password_hash.verify_and_update(
            password, enrollment.password_hash
        )
        if not valid:
            logger.warning(
                "Password verification failed: invalid password",
                extra={"identity_id": identity_id},
            )
            raise InvalidPasswordException()
        if replacement is not None:
            enrollment = dataclasses.replace(enrollment, password_hash=replacement)
            await self.update(enrollment)
        logger.info("Password verified", extra={"identity_id": identity_id})
        return enrollment

    async def forgot_password(self, identity_id: typing.Any) -> str:
        """Replace the pending reset credential; deliver the returned token after commit.

        Args:
            identity_id: The ID of the identity whose password state is accessed.

        Returns:
            The raw reset token, for delivery after commit.
        """
        logger.debug("Password reset requested", extra={"identity_id": identity_id})
        enrollment = await self._require_enrollment(identity_id)
        token = await self.token_provider.generate()
        await self.update(
            dataclasses.replace(
                enrollment,
                reset_token_identifier=token.identifier,
                reset_token_verifier=token.verifier,
                reset_token_expires_at=get_current_timestamp()
                + int(self.reset_lifetime.total_seconds()),
            )
        )
        logger.info("Password reset token created", extra={"identity_id": identity_id})
        return token.token

    async def reset_password(self, token: str, new_password: str) -> PasswordEnrollment:
        """Consume a reset token and replace the password atomically.

        Args:
            token: The raw password reset token.
            new_password: The new plaintext password.

        Returns:
            The updated enrollment.

        Raises:
            InvalidPasswordResetTokenException: The token is invalid, expired, or consumed.
        """
        logger.debug("Password reset attempted")
        try:
            parts = self.token_provider.parse(token)
        except InvalidTokenException as exc:
            logger.warning("Password reset failed: malformed token")
            raise InvalidPasswordResetTokenException() from exc
        enrollment = await self.get_by_reset_token_identifier(parts.identifier)
        if (
            enrollment is None
            or enrollment.password_hash is None
            or enrollment.reset_token_verifier is None
            or enrollment.reset_token_expires_at is None
            or get_current_timestamp() >= enrollment.reset_token_expires_at
        ):
            logger.warning(
                "Password reset failed: missing or expired token",
                extra={
                    "identity_id": enrollment.identity_id
                    if enrollment is not None
                    else None
                },
            )
            raise InvalidPasswordResetTokenException()
        valid, _ = await self.token_provider.verify_and_update(
            parts.secret, enrollment.reset_token_verifier
        )
        if not valid:
            logger.warning(
                "Password reset failed: invalid token",
                extra={"identity_id": enrollment.identity_id},
            )
            raise InvalidPasswordResetTokenException()
        enrollment = await self._set_password(enrollment, new_password)
        logger.info(
            "Password reset completed", extra={"identity_id": enrollment.identity_id}
        )
        return enrollment

    async def update_password(
        self, identity_id: typing.Any, current_password: str, new_password: str
    ) -> PasswordEnrollment:
        """Verify the current password and replace it, clearing pending resets.

        Args:
            identity_id: The ID of the identity whose password state is accessed.
            current_password: The current plaintext password to verify.
            new_password: The new plaintext password.

        Returns:
            The updated enrollment.

        Raises:
            InvalidPasswordException: The current password does not match.
        """
        logger.debug("Password update attempted", extra={"identity_id": identity_id})
        enrollment = await self._require_enrollment(identity_id)
        assert enrollment.password_hash is not None
        if not self.password_hash.verify(current_password, enrollment.password_hash):
            logger.warning(
                "Password update failed: invalid password",
                extra={"identity_id": identity_id},
            )
            raise InvalidPasswordException()
        enrollment = await self._set_password(enrollment, new_password)
        logger.info("Password updated", extra={"identity_id": identity_id})
        return enrollment

    async def _require_enrollment(self, identity_id: typing.Any) -> PasswordEnrollment:
        enrollment = await self.get_enrollment(identity_id)
        if enrollment is None:
            logger.warning(
                "Password operation failed: not enrolled",
                extra={"identity_id": identity_id},
            )
            raise NotEnrolledPasswordException()
        return enrollment

    async def _set_password(
        self, enrollment: PasswordEnrollment, password: str
    ) -> PasswordEnrollment:
        enrollment = dataclasses.replace(
            enrollment,
            password_hash=self.password_hash.hash(password),
            reset_token_identifier=None,
            reset_token_verifier=None,
            reset_token_expires_at=None,
        )
        await self.update(enrollment)
        return enrollment

    @abc.abstractmethod
    async def get_by_identity_id(
        self, identity_id: typing.Any
    ) -> PasswordEnrollment | None:
        """Read password state, including identities without a password.

        Args:
            identity_id: The ID of the identity whose password state is accessed.

        Abstract: Implementation contract
            Match the identity and configured factor. Return None only for a missing
            identity. Protect the identity before reading, including when its password
            is unset, and retain protection until the transaction ends. All password
            and reset operations must share this protection. Leave commit and rollback
            to the caller. This method does not create missing identities.
        """
        ...

    @abc.abstractmethod
    async def get_by_reset_token_identifier(
        self, identifier: str
    ) -> PasswordEnrollment | None:
        """Read password state by reset token identifier, including expired tokens.

        Args:
            identifier: The reset token identifier to look up.

        Abstract: Implementation contract
            Match the identifier and configured factor. Protect the identity before
            reading its password and reset fields; recheck the identifier after
            acquiring protection. Return None when no match remains. Retain the same
            identity protection used by all password operations until the transaction
            ends. Leave commit and rollback to the caller.
        """
        ...

    @abc.abstractmethod
    async def update(self, enrollment: PasswordEnrollment) -> None:
        """Persist password state on an existing identity.

        Args:
            enrollment: The password enrollment to persist.

        Abstract: Implementation contract
            Update only password and reset fields for the supplied record ID under
            transaction-long identity protection. Persist these fields atomically;
            preserve other application columns. Enforce uniqueness of non-null reset
            identifiers within the configured factor. Translate identifier collisions
            to TokenIdentifierCollision without changing stored credentials or aborting
            the caller's transaction. Leave commit and rollback to the caller.
        """
        ...


__all__ = [
    "AlreadyEnrolledPasswordException",
    "IdentityNotFoundException",
    "InvalidPasswordException",
    "InvalidPasswordResetTokenException",
    "NotEnrolledPasswordException",
    "PasswordEnrollment",
    "PasswordException",
    "PasswordFactor",
    "PasswordHash",
    "PasswordHashException",
    "PasswordHashGenerationException",
    "PasswordHashVerificationException",
]
