import base64
import hashlib
import secrets
import typing

CodeChallengeMethod = typing.Literal["S256", "plain"]


def generate_code_verifier() -> str:
    """Generate a PKCE code_verifier as per RFC 7636 Section 4.1.

    Uses a cryptographically secure random number generator to create a
    high-entropy string using the unreserved URI character set:
    ALPHA / DIGIT / "-" / "." / "_" / "~"

    Returns:
        A cryptographically random string of ~86 characters, within the
        RFC 7636 range of 43-128 characters, with 512 bits of entropy.
    """
    return secrets.token_urlsafe(64)


def generate_code_challenge(code_verifier: str, method: CodeChallengeMethod) -> str:
    """Generate a PKCE code_challenge from a code_verifier as per RFC 7636.

    Args:
        code_verifier: The code verifier string.
        method: The code challenge method. Either "S256" or "plain".

    Returns:
        The code challenge string.
    """
    match method:
        case "S256":
            digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
            return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
        case "plain":
            return code_verifier


__all__ = ["CodeChallengeMethod", "generate_code_challenge", "generate_code_verifier"]
