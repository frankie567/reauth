import collections.abc
import hmac
import re

from reauth.tokens.base import TokenGenerationException, TokenVerificationException


class HMACTokenVerifier:
    """HMAC-SHA256 with explicitly retained keys and lazy key rotation.

    Keys must be at least 32 bytes. Verifiers encode format, key ID and MAC as
    ``hmac-sha256$1$key_id$hex_mac``. Unknown keys fail operationally, rather
    than being mistaken for invalid credentials. Key retirement is manual.
    """

    def __init__(
        self, *, current_key_id: str, keys: collections.abc.Mapping[str, bytes]
    ) -> None:
        if current_key_id not in keys or any(
            re.fullmatch(r"[A-Za-z0-9_-]{1,64}", key_id) is None
            or not isinstance(key, bytes)
            or len(key) < 32
            for key_id, key in keys.items()
        ):
            message = "Provide named keys of at least 32 bytes and a current key"
            raise ValueError(message)
        self.current_key_id = current_key_id
        self._keys = dict(keys)

    def _create(self, secret: str, key_id: str) -> str:
        mac = hmac.new(self._keys[key_id], secret.encode("utf-8"), "sha256")
        return f"hmac-sha256$1${key_id}${mac.hexdigest()}"

    async def create(self, secret: str) -> str:
        """Create a verifier with the current key.

        Returns:
            The opaque, versioned verifier.

        Raises:
            TokenGenerationException: If the secret cannot be encoded.
        """
        try:
            return self._create(secret, self.current_key_id)
        except UnicodeEncodeError as error:
            message = "Verifier creation failed"
            raise TokenGenerationException(message) from error

    async def verify_and_update(
        self, secret: str, verifier: str
    ) -> tuple[bool, str | None]:
        """Verify retained keys and upgrade successful matches to the current key.

        Returns:
            Whether the secret matches and an optional current-key verifier.

        Raises:
            TokenVerificationException: If the stored format or key is unavailable,
                or a successful verification cannot be upgraded.
        """
        match = re.fullmatch(
            r"hmac-sha256\$1\$([A-Za-z0-9_-]{1,64})\$[0-9a-f]{64}", verifier
        )
        if match is None:
            message = "Unsupported stored verifier"
            raise TokenVerificationException(message)
        key_id = match[1]
        if key_id not in self._keys:
            message = "Verification key unavailable"
            raise TokenVerificationException(message)
        try:
            expected = self._create(secret, key_id)
        except UnicodeEncodeError:
            return False, None
        if not hmac.compare_digest(expected, verifier):
            return False, None
        if key_id == self.current_key_id:
            return True, None
        try:
            replacement = await self.create(secret)
        except TokenGenerationException as error:
            message = "Verifier upgrade failed"
            raise TokenVerificationException(message) from error
        return True, replacement
