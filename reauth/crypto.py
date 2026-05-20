"""A set of cryptographic utilities."""

import hashlib
import hmac
import secrets
import string
import typing
import zlib

TokenHash = typing.NewType("TokenHash", str)


def _crc32_to_base62(number: int) -> str:
    characters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    base = len(characters)
    encoded = ""
    while number:
        number, remainder = divmod(number, base)
        encoded = characters[remainder] + encoded
    return encoded.zfill(6)  # Ensure the checksum is 6 characters long


def get_token_hash(token: str, *, secret: str) -> TokenHash:
    """Compute HMAC-SHA256 hash of a token.

    Args:
        token: The token value to hash.
        secret: The secret key used for HMAC computation.

    Returns:
        Hexadecimal string of the HMAC-SHA256 hash.
    """
    hash = hmac.new(secret.encode("ascii"), token.encode("ascii"), hashlib.sha256)
    return TokenHash(hash.hexdigest())


def generate_token(*, prefix: str = "") -> str:
    """Generate a high-entropy random token with embedded checksum.

    The token consists of a random string of 37 alphanumeric characters
    followed by a 6-character base62-encoded CRC32 checksum.

    The CRC32 checksum provides fast pre-validation to filter out malformed
    or corrupted tokens before more expensive HMAC verification or database
    lookups. It is NOT a cryptographic security mechanism.

    Args:
        prefix: Optional prefix prepended to the generated token.

    Returns:
        A token string with format: {prefix}{37_random_chars}{6_checksum_chars}.
    """
    # Generate a high entropy random token
    token = "".join(
        secrets.choice(string.ascii_letters + string.digits) for _ in range(37)
    )

    # Calculate a 32-bit CRC checksum
    checksum = zlib.crc32(token.encode("utf-8")) & 0xFFFFFFFF
    checksum_base62 = _crc32_to_base62(checksum)

    # Concatenate the prefix, token, and checksum
    return f"{prefix}{token}{checksum_base62}"


def generate_token_hash_pair(*, secret: str, prefix: str = "") -> tuple[str, TokenHash]:
    """Generate a token and its HMAC-SHA256 hash pair.

    Generates a high-entropy token with embedded checksum and computes its
    HMAC-SHA256 hash using the provided secret. This pattern allows storing
    only the hash in the database while the raw token is provided to the user.

    Args:
        secret: The secret key used for HMAC computation.
        prefix: Optional prefix prepended to the generated token.

    Returns:
        A tuple of (token, hash) where token is the raw value and hash is
        its HMAC-SHA256 hexadecimal digest.
    """
    token = generate_token(prefix=prefix)
    return token, get_token_hash(token, secret=secret)


def generate_code_hash_pair(*, secret: str, length: int = 6) -> tuple[str, TokenHash]:
    """Generate a 6-alphanumeric code and its HMAC-SHA256 hash pair.

    This is useful for generating OTP codes where the raw code is sent to the
    user and only the hash is stored for verification.

    Args:
        secret: The secret key used for HMAC computation.
        length: The length of the numeric code to generate (default is 6).

    Returns:
        A tuple of (code, hash) where code is the raw code and hash is
        its HMAC-SHA256 hexadecimal digest.
    """
    code = "".join(
        secrets.choice(string.ascii_uppercase + string.digits) for _ in range(length)
    )
    code_hash = get_token_hash(code, secret=secret)
    return code, code_hash


__all__ = [
    "TokenHash",
    "generate_code_hash_pair",
    "generate_token",
    "generate_token_hash_pair",
    "get_token_hash",
]
