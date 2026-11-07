import secrets
import string
import zlib

from reauth.tokens.base import (
    GeneratedToken,
    InvalidTokenException,
    TokenParts,
    TokenVerifier,
)

ALPHABET = string.ascii_letters + string.digits


def _checksum(value: str) -> str:
    number = zlib.crc32(value.encode("ascii"))
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    encoded = ""
    while number:
        number, remainder = divmod(number, 62)
        encoded = alphabet[remainder] + encoded
    return encoded.zfill(6)


class ChecksummedTokenProvider:
    """Fixed format: prefix, 16-character identifier, 32-character secret, CRC32.

    CRC32 is a corruption check, not authentication. Change the prefix when
    introducing incompatible component lengths. Identifiers have ~95 bits of
    entropy; secrets have ~190 bits. Storage must enforce identifier uniqueness.
    """

    def __init__(self, *, prefix: str, verifier: TokenVerifier) -> None:
        if (
            not prefix.isascii()
            or not prefix
            or any(character not in ALPHABET + "_-" for character in prefix)
        ):
            message = "Prefix must contain ASCII letters, digits, '_' or '-'"
            raise ValueError(message)
        self.prefix = prefix
        self.verifier = verifier

    async def generate(self) -> GeneratedToken:
        """Generate independently random identifier and secret components.

        Returns:
            The complete token, public identifier and opaque verifier.

        """
        identifier = "".join(secrets.choice(ALPHABET) for _ in range(16))
        secret = "".join(secrets.choice(ALPHABET) for _ in range(32))
        value = self.prefix + identifier + secret
        return GeneratedToken(
            value + _checksum(value), identifier, await self.verifier.create(secret)
        )

    def parse(self, token: str) -> TokenParts:
        """Validate the complete format and checksum before any storage lookup.

        Returns:
            The public identifier and secret.

        Raises:
            InvalidTokenException: If the prefix, length, alphabet or checksum differs.
        """
        if not token.startswith(self.prefix):
            raise InvalidTokenException()
        value = token[len(self.prefix) :]
        if len(value) != 54 or any(character not in ALPHABET for character in value):
            raise InvalidTokenException()
        if _checksum(token[:-6]) != value[-6:]:
            raise InvalidTokenException()
        return TokenParts(value[:16], value[16:48])

    async def verify_and_update(
        self, secret: str, verifier: str
    ) -> tuple[bool, str | None]:
        """Delegate secret verification and upgrades to the injected verifier.

        Returns:
            Whether the secret matches, and an optional replacement verifier.
        """
        return await self.verifier.verify_and_update(secret, verifier)
