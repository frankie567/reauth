import typing

from reauth.exceptions import ReauthException


class PasswordHashException(ReauthException):
    """Base exception for password hashing failures."""


class PasswordHashGenerationException(PasswordHashException):
    """Password hashing failed."""


class PasswordHashVerificationException(PasswordHashException):
    """Stored hash verification or upgrade failed."""


class PasswordHash(typing.Protocol):
    """Synchronous password hashing; programming errors propagate unchanged."""

    def hash(self, password: str | bytes, *, salt: bytes | None = None) -> str:
        """Hash a password.

        Args:
            password: The plaintext password.
            salt: An explicit salt, or None to generate a random salt.

        Abstract: Implementation contract
            Return a salted password hash. Raise PasswordHashGenerationException
            for backend failures, preserving the cause. Do not log credentials.
        """
        ...

    def verify(self, password: str | bytes, hash: str | bytes) -> bool:
        """Verify a password.

        Args:
            password: The plaintext password.
            hash: The stored encoded password hash.

        Abstract: Implementation contract
            Return False for a mismatch. Raise PasswordHashVerificationException
            for malformed or unsupported hashes and backend failures, preserving
            the cause. Do not log credentials.
        """
        ...

    def verify_and_update(
        self, password: str | bytes, hash: str | bytes
    ) -> tuple[bool, str | None]:
        """Verify a password and optionally upgrade its hash.

        Args:
            password: The plaintext password.
            hash: The stored encoded password hash.

        Abstract: Implementation contract
            Return (False, None) for a mismatch or (True, replacement) on success,
            where replacement is None if no upgrade is needed. Raise
            PasswordHashVerificationException for malformed or unsupported hashes,
            backend failures, or upgrade failures, preserving the cause.
            Do not log credentials.
        """
        ...
