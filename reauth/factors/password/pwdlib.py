import pwdlib
import pwdlib.exceptions

from reauth.factors.password.hashing import (
    PasswordHashGenerationException,
    PasswordHashVerificationException,
)


class PwdlibPasswordHash:
    """Password hashing using pwdlib's recommended configuration.

    Implements the PasswordHash protocol with synchronous hashing, verification,
    and automatic hash upgrades. Translates operational failures into Reauth
    exceptions while preserving their original causes.
    """

    def __init__(self) -> None:
        self._impl = pwdlib.PasswordHash.recommended()

    def hash(self, password: str | bytes, *, salt: bytes | None = None) -> str:
        """Hash a password.

        Args:
            password: The plaintext password.
            salt: An explicit salt, or None to generate a random salt.

        Returns:
            The encoded hash.

        Raises:
            PasswordHashGenerationException: If hashing fails.
        """
        try:
            return self._impl.hash(password, salt=salt)
        except (pwdlib.exceptions.PwdlibError, UnicodeError) as exc:
            raise PasswordHashGenerationException() from exc

    def verify(self, password: str | bytes, hash: str | bytes) -> bool:
        """Verify a password.

        Args:
            password: The plaintext password.
            hash: The stored encoded password hash.

        Returns:
            Whether the password matches.

        Raises:
            PasswordHashVerificationException: If verification fails operationally.
        """
        try:
            return self._impl.verify(password, hash)
        except (pwdlib.exceptions.PwdlibError, UnicodeError) as exc:
            raise PasswordHashVerificationException() from exc

    def verify_and_update(
        self, password: str | bytes, hash: str | bytes
    ) -> tuple[bool, str | None]:
        """Verify and upgrade an outdated hash.

        Args:
            password: The plaintext password.
            hash: The stored encoded password hash.

        Returns:
            Whether the password matches and an optional replacement hash.

        Raises:
            PasswordHashVerificationException: If verification or upgrading fails.
        """
        try:
            return self._impl.verify_and_update(password, hash)
        except (pwdlib.exceptions.PwdlibError, UnicodeError) as exc:
            raise PasswordHashVerificationException() from exc
